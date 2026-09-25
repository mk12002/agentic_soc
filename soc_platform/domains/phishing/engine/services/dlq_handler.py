"""
Dead Letter Queue (DLQ) Handler Service.
Consumes failed messages, attempts retries with backoff, and routes to poison queue.
"""

import time

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.messaging_service import RabbitMQClient
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("dlq_handler")

class DLQHandler:
    def __init__(self):
        self.client = RabbitMQClient()
        self.poison_queue = settings.rabbitmq_poison_queue

    def start(self):
        """Start consuming from the DLQ."""
        logger.info("Starting DLQ Handler", queue=settings.rabbitmq_dead_letter_queue)
        
        # We need to declare the poison queue first
        self.client.channel.queue_declare(queue=self.poison_queue, durable=True)
        
        # Consume from DLQ
        # We use a custom callback to access headers
        self.client.channel.basic_consume(
            queue=settings.rabbitmq_dead_letter_queue,
            on_message_callback=self._handle_dead_letter
        )
        self.client.channel.start_consuming()

    def _handle_dead_letter(self, ch, method, properties, body):
        """Process a dead-lettered message."""
        delivery_tag = method.delivery_tag
        headers = properties.headers or {}
        x_death = headers.get("x-death", [])
        
        retry_count = 0
        original_exchange = ""
        original_routing_key = ""
        
        if x_death:
            # x-death is a list of dicts. The first one is the most recent.
            recent_death = x_death[0]
            retry_count = recent_death.get("count", 0)
            original_exchange = recent_death.get("exchange", "")
            original_routing_key = recent_death.get("routing-keys", [""])[0]
        
        logger.info(
            "Processing dead letter",
            retry_count=retry_count,
            exchange=original_exchange,
            routing_key=original_routing_key
        )

        try:
            if retry_count < settings.rabbitmq_max_retries:
                # Calculate backoff for retry
                backoff = min(
                    settings.rabbitmq_backoff_max,
                    settings.rabbitmq_backoff_base * (2 ** retry_count)
                )
                logger.info("Retrying message", backoff=backoff, retry_count=retry_count + 1)
                time.sleep(backoff)
                
                # Republish to original destination
                # Note: basic_publish will trigger a new dead-lettering if it fails again
                ch.basic_publish(
                    exchange=original_exchange,
                    routing_key=original_routing_key,
                    body=body,
                    properties=properties # Keep original properties (including headers)
                )
                logger.info("Message republished for retry")
            else:
                # Max retries reached, move to poison queue
                logger.warning("Max retries reached, moving to poison queue", retry_count=retry_count)
                ch.basic_publish(
                    exchange="",
                    routing_key=self.poison_queue,
                    body=body,
                    properties=properties
                )
                logger.info("Message moved to poison queue")

            # Acknowledge the message from DLQ
            ch.basic_ack(delivery_tag=delivery_tag)
            
        except Exception as exc:
            logger.exception("Failed to handle dead letter", error=str(exc))
            # Nack and requeue in DLQ if we failed to process it (e.g. RabbitMQ down)
            ch.basic_nack(delivery_tag=delivery_tag, requeue=True)

if __name__ == "__main__":
    handler = DLQHandler()
    try:
        handler.start()
    except KeyboardInterrupt:
        logger.info("DLQ Handler stopped by user")
        handler.client.shutdown()
