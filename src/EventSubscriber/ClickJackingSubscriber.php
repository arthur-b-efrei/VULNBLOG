<?php

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class ClickJackingSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => ['onKernelResponse', -10],
        ];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        $response = $event->getResponse();
        
        // Protection contre le ClickJacking
        // X-Frame-Options pour compatibilité avec les anciens navigateurs
        $response->headers->set('X-Frame-Options', 'DENY');
        
        // Content-Security-Policy avec frame-ancestors (plus moderne et flexible)
        $response->headers->set('Content-Security-Policy', "frame-ancestors 'none'");
    }
}

