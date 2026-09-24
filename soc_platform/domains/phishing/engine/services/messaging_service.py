"""
RabbitMQ messaging helpers for event-driven agent communication.
"""

import json
import threading
import gzip
import time
import io
import traceback
from threading import Event
from typing import Any, Callable

import pika
from concurrent.futures import ThreadPoolExecutor

try:
    from prometheus_client import Histogram, Gauge
    from prometheus_client import core as prometheus_core

    # Lightweight no-op metric used when a metric is already registered or in tests
    class MockMetric:
        def labels(self, *args, **kwargs):
            return self

        def observe(self, *args, **kwargs):
            pass

        def inc(self, *args, **kwargs):
            pass

        def dec(self, *args, **kwargs):
            pass

        def set(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    # Guard metric registration to avoid duplicate timeseries during test re-imports
    def _safe_histogram(name, documentation, labels):
        try:
            return Histogram(name, documentation, labels)
        except ValueError:
            # Already registered — return a lightweight no-op wrapper
            return MockMetric()

    def _safe_gauge(name, documentation):
        try:
            return Gauge(name, documentation)
        except ValueError:
            return MockMetric()

    RABBITMQ_PUBLISH_DURATION = _safe_histogram(
        "rabbitmq_publish_duration_ms",
        "Duration of RabbitMQ publish operations in ms",
        ["exchange", "routing_key"],
    )
    RABBITMQ_CONSUME_DURATION = _safe_histogram(
        "rabbitmq_consume_duration_ms",
        "Duration of message processing in ms",
        ["queue"],
    )
    RABBITMQ_ACTIVE_CONNECTIONS = _safe_gauge(
        "rabbitmq_active_connections", "Number of active RabbitMQ connections"
    )
except ImportError:
    # Fallback if prometheus_client is not installed
    class MockMetric:
        def labels(self, *args, **kwargs):
            return self

        def observe(self, *args, **kwargs):
            pass

        def inc(self, *args, **kwargs):
            pass

        def dec(self, *args, **kwargs):
            pass

        def set(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    RABBITMQ_PUBLISH_DURATION = MockMetric()
    RABBITMQ_CONSUME_DURATION = MockMetric()
    RABBITMQ_ACTIVE_CONNECTIONS = MockMetric()

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("messaging_service")


class RabbitMQClient:
    """Small wrapper around pika BlockingConnection for publish/consume flows."""

    def __init__(self):
        self._connection: pika.BlockingConnection | None = None
        self._channel: pika.adapters.blocking_connection.BlockingChannel | None = None
        # Worker pool used to execute message handling without blocking the pika I/O loop
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._consumer_thread_id: int | None = None
        # Circuit breaker state
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._circuit_open = False
        self._is_shutting_down = False

    @property
    def channel(self) -> pika.adapters.blocking_connection.BlockingChannel:
        if self._channel is None or self._channel.is_closed:
            self.connect()
        return self._channel

    def connect(self) -> None:
        """Establish connection with exponential backoff and circuit breaker logic."""
        if self._is_shutting_down:
            return

        # Check circuit breaker status
        if self._circuit_open:
            if time.time() - self._last_failure_time > settings.rabbitmq_circuit_breaker_timeout:
                logger.info("Circuit breaker timeout reached, attempting reset")
                self._circuit_open = False
                self._failure_count = 0
            else:
                raise ConnectionError("RabbitMQ circuit breaker is OPEN. Skipping connection attempt.")

        credentials = pika.PlainCredentials(
            settings.rabbitmq_user,
            settings.rabbitmq_password,
        )
        parameters = pika.ConnectionParameters(
            host=settings.rabbitmq_host,
            port=settings.rabbitmq_port,
            credentials=credentials,
            heartbeat=int(getattr(settings, "rabbitmq_heartbeat_seconds", 600)),
            blocked_connection_timeout=int(getattr(settings, "rabbitmq_blocked_connection_timeout_seconds", 600)),
        )

        retries = 0
        while retries <= settings.rabbitmq_max_retries:
            try:
                self._connection = pika.BlockingConnection(parameters)
                self._channel = self._connection.channel()
                self._declare_dead_letter_topology()

                # Reset circuit breaker on success
                self._failure_count = 0
                self._circuit_open = False
                RABBITMQ_ACTIVE_CONNECTIONS.inc()

                logger.info("RabbitMQ connected", host=settings.rabbitmq_host, port=settings.rabbitmq_port)
                return
            except Exception as exc:
                retries += 1
                self._failure_count += 1
                self._last_failure_time = time.time()

                if self._failure_count >= settings.rabbitmq_circuit_breaker_threshold:
                    self._circuit_open = True
                    logger.error("RabbitMQ circuit breaker OPENED due to multiple failures", error=str(exc))
                    raise ConnectionError(f"Failed to connect after {retries} retries. Circuit breaker opened.") from exc

                if retries > settings.rabbitmq_max_retries:
                    logger.error("RabbitMQ connection failed after max retries", retries=retries, error=str(exc))
                    raise

                backoff = min(
                    settings.rabbitmq_backoff_max,
                    settings.rabbitmq_backoff_base * (2 ** (retries - 1))
                )
                logger.warning(
                    "RabbitMQ connection failed, retrying...",
                    retry=retries,
                    backoff=backoff,
                    error=str(exc),
                )
                time.sleep(backoff)

    def _declare_dead_letter_topology(self) -> None:
        self.channel.exchange_declare(
            exchange=settings.rabbitmq_dead_letter_exchange,
            exchange_type="direct",
            durable=True,
        )
        self.channel.queue_declare(queue=settings.rabbitmq_dead_letter_queue, durable=True)
        self.channel.queue_bind(
            queue=settings.rabbitmq_dead_letter_queue,
            exchange=settings.rabbitmq_dead_letter_exchange,
            routing_key=settings.rabbitmq_dead_letter_queue,
        )

    def _queue_arguments(self) -> dict[str, str]:
        return {
            "x-dead-letter-exchange": settings.rabbitmq_dead_letter_exchange,
            "x-dead-letter-routing-key": settings.rabbitmq_dead_letter_queue,
        }

    def _compress(self, body: bytes) -> tuple[bytes, str | None]:
        """Compress body if it exceeds threshold and compression is enabled."""
        if not settings.enable_message_compression:
            return body, None
        if len(body) < settings.compression_threshold_kb * 1024:
            return body, None

        try:
            out = io.BytesIO()
            with gzip.GzipFile(fileobj=out, mode="wb") as f:
                f.write(body)
            compressed_body = out.getvalue()

            reduction = (1 - len(compressed_body) / len(body)) * 100
            logger.debug(
                "Message compressed",
                original_size=len(body),
                compressed_size=len(compressed_body),
                reduction_pct=f"{reduction:.1f}%",
            )
            return compressed_body, "gzip"
        except Exception as exc:
            logger.warning("Compression failed, sending uncompressed", error=str(exc))
            return body, None

    def _decompress(self, body: bytes, content_encoding: str | None) -> bytes:
        """Decompress body if content_encoding is gzip."""
        if content_encoding != "gzip":
            return body

        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as f:
                return f.read()
        except Exception as exc:
            logger.error("Decompression failed", error=str(exc))
            raise

    def close(self) -> None:
        """Close RabbitMQ connection and channel."""
        if self._connection and self._connection.is_open:
            try:
                self._connection.close()
                RABBITMQ_ACTIVE_CONNECTIONS.dec()
                logger.info("RabbitMQ connection closed")
            except Exception:
                pass
        self._connection = None
        self._channel = None
        self._consumer_thread_id = None

    def shutdown(self, timeout: int = 30) -> None:
        """Gracefully shutdown the client, stopping consumption and waiting for workers."""
        logger.info("Graceful shutdown initiated", timeout=timeout)
        self._is_shutting_down = True

        # Stop consuming if we are currently consuming
        try:
            if self._channel and self._channel.is_open:
                # stop_consuming must be called from the I/O thread if we are in start_consuming()
                # or via add_callback_threadsafe if called from another thread.
                if threading.get_ident() == self._consumer_thread_id:
                    self._channel.stop_consuming()
                else:
                    self._connection.add_callback_threadsafe(self._channel.stop_consuming)
                logger.info("Stopped RabbitMQ consumption")
        except Exception as exc:
            logger.warning("Error stopping consumption", error=str(exc))

        # Shutdown executor and wait for workers
        try:
            # We don't have a direct way to enforce the timeout on ThreadPoolExecutor.shutdown
            # but we can call it with wait=True.
            self._executor.shutdown(wait=True)
            logger.info("Message worker pool shutdown complete")
        except Exception as exc:
            logger.warning("Error during worker pool shutdown", error=str(exc))

        self.close()

    def declare_new_email_fanout(self, queue_name: str) -> None:
        self.channel.exchange_declare(
            exchange=settings.new_email_exchange,
            exchange_type="fanout",
            durable=True,
        )
        self.channel.queue_declare(queue=queue_name, durable=True, arguments=self._queue_arguments())
        self.channel.queue_bind(queue=queue_name, exchange=settings.new_email_exchange)

    def declare_results_queue(self, queue_name: str | None = None) -> str:
        queue_name = queue_name or settings.results_queue
        self.channel.queue_declare(queue=queue_name, durable=True, arguments=self._queue_arguments())
        return queue_name

    def publish_new_email(self, payload: dict[str, Any]) -> None:
        self.channel.exchange_declare(
            exchange=settings.new_email_exchange,
            exchange_type="fanout",
            durable=True,
        )
        body = json.dumps(payload).encode("utf-8")
        body, encoding = self._compress(body)

        start_time = time.perf_counter()
        self.channel.basic_publish(
            exchange=settings.new_email_exchange,
            routing_key="",
            body=body,
            properties=pika.BasicProperties(
                delivery_mode=2,
                content_encoding=encoding,
            ),
        )
        duration_ms = (time.perf_counter() - start_time) * 1000
        RABBITMQ_PUBLISH_DURATION.labels(exchange=settings.new_email_exchange, routing_key="").observe(duration_ms)

    def publish_to_queue(self, queue_name: str, payload: dict[str, Any]) -> None:
        def _do_publish() -> None:
            self.channel.queue_declare(queue=queue_name, durable=True, arguments=self._queue_arguments())
            body = json.dumps(payload).encode("utf-8")
            body, encoding = self._compress(body)

            start_time = time.perf_counter()
            self.channel.basic_publish(
                exchange="",
                routing_key=queue_name,
                body=body,
                properties=pika.BasicProperties(
                    delivery_mode=2,
                    content_encoding=encoding,
                ),
            )
            duration_ms = (time.perf_counter() - start_time) * 1000
            RABBITMQ_PUBLISH_DURATION.labels(exchange="", routing_key=queue_name).observe(duration_ms)

        # BlockingConnection channels are not thread-safe. If called from a worker thread,
        # marshal the publish back to the pika I/O thread and wait for completion.
        if (
            self._connection
            and self._connection.is_open
            and self._consumer_thread_id is not None
            and threading.get_ident() != self._consumer_thread_id
        ):
            done = Event()
            error: list[Exception] = []

            def _publish_on_io_thread() -> None:
                try:
                    _do_publish()
                except Exception as exc:
                    error.append(exc)
                finally:
                    done.set()

            self._connection.add_callback_threadsafe(_publish_on_io_thread)
            done.wait(timeout=10)
            if error:
                raise error[0]
            if not done.is_set():
                raise TimeoutError("Timed out waiting for RabbitMQ publish on I/O thread")
            return

        _do_publish()

    def consume(
        self,
        queue_name: str,
        callback: Callable[[dict[str, Any]], None],
        prefetch_count: int = 1,
    ) -> None:
        """
        Consume messages from `queue_name` without blocking the pika I/O loop during long processing.

        Messages are handed off to a thread pool; acknowledgements are scheduled back on the
        pika connection thread via `add_callback_threadsafe` to remain thread-safe.
        """
        self.channel.queue_declare(queue=queue_name, durable=True, arguments=self._queue_arguments())
        self.channel.basic_qos(prefetch_count=prefetch_count)
        self._consumer_thread_id = threading.get_ident()

        def _wrapped(ch, method, _properties, body):
            delivery_tag = method.delivery_tag

            def _worker():
                try:
                    encoding = getattr(_properties, "content_encoding", None)
                    decompressed_body = self._decompress(body, encoding)
                    payload = json.loads(decompressed_body.decode("utf-8"))
                except Exception as exc:
                    logger.exception("Failed to decode message body", error=str(exc), queue=queue_name)
                    # Schedule a nack for malformed payloads
                    try:
                        self._connection.add_callback_threadsafe(lambda: ch.basic_nack(delivery_tag=delivery_tag, requeue=False))
                    except Exception:
                        pass
                    return

                try:
                    start_time = time.perf_counter()
                    callback(payload)
                    duration_ms = (time.perf_counter() - start_time) * 1000
                    RABBITMQ_CONSUME_DURATION.labels(queue=queue_name).observe(duration_ms)
                    
                    # Ack must be performed on the pika I/O thread
                    try:
                        self._connection.add_callback_threadsafe(lambda: ch.basic_ack(delivery_tag=delivery_tag))
                    except Exception:
                        logger.warning("Failed to schedule ack on pika thread", queue=queue_name)
                except Exception as exc:
                    logger.exception("Message processing failed in worker", error=str(exc), queue=queue_name)
                    try:
                        self._connection.add_callback_threadsafe(lambda: ch.basic_nack(delivery_tag=delivery_tag, requeue=False))
                    except Exception:
                        logger.warning("Failed to schedule nack on pika thread", queue=queue_name)

            # Submit the worker and return immediately so pika can service heartbeats
            try:
                self._executor.submit(_worker)
            except Exception as exc:
                logger.exception("Failed to submit message worker", error=str(exc), queue=queue_name)
                try:
                    ch.basic_nack(delivery_tag=delivery_tag, requeue=False)
                except Exception:
                    pass

        self.channel.basic_consume(queue=queue_name, on_message_callback=_wrapped)
        logger.info("Consuming queue", queue=queue_name)
        self.channel.start_consuming()

    def get_queue_stats(self, queue_name: str) -> dict[str, Any]:
        """Return queue depth and consumer count for a queue if it exists."""
        try:
            queue = self.channel.queue_declare(queue=queue_name, passive=True)
            method = queue.method
            return {
                "queue": queue_name,
                "exists": True,
                "messages_ready": int(getattr(method, "message_count", 0) or 0),
                "consumers": int(getattr(method, "consumer_count", 0) or 0),
            }
        except Exception as exc:
            return {
                "queue": queue_name,
                "exists": False,
                "messages_ready": 0,
                "consumers": 0,
                "error": str(exc),
            }

    def get_multi_queue_stats(self, queue_names: list[str]) -> list[dict[str, Any]]:
        """Return stats for multiple queues in a single connection lifecycle."""
        return [self.get_queue_stats(name) for name in queue_names]
