<?php

namespace Tykfyr\OpenIDConnect\Tests;

use Tykfyr\OpenIDConnect\Client;
use PHPUnit\Framework\TestCase;

class ClientTest extends TestCase
{
    private Client $client;
    private string $providerUrl = 'https://example.com';
    private string $clientId = 'test-client-id';
    private string $clientSecret = 'test-client-secret';

    protected function setUp(): void
    {
        $this->client = new Client($this->providerUrl, $this->clientId, $this->clientSecret);
    }

    public function testConstructor(): void
    {
        $this->assertInstanceOf(Client::class, $this->client);
    }

    public function testSetScopes(): void
    {
        $scopes = ['openid', 'profile'];
        $this->client->setScopes($scopes);
        
        // Use reflection to access private property
        $reflection = new \ReflectionClass($this->client);
        $property = $reflection->getProperty('scopes');
        $property->setAccessible(true);
        
        $this->assertEquals($scopes, $property->getValue($this->client));
    }

    public function testSetRedirectUri(): void
    {
        $redirectUri = 'https://example.com/callback';
        $this->client->setRedirectUri($redirectUri);
        
        $reflection = new \ReflectionClass($this->client);
        $property = $reflection->getProperty('redirectUri');
        $property->setAccessible(true);
        
        $this->assertEquals($redirectUri, $property->getValue($this->client));
    }

    public function testSetVerifyHost(): void
    {
        $this->client->setVerifyHost(false);
        
        $reflection = new \ReflectionClass($this->client);
        $property = $reflection->getProperty('verifyHost');
        $property->setAccessible(true);
        
        $this->assertFalse($property->getValue($this->client));
    }

    public function testSetVerifyPeer(): void
    {
        $this->client->setVerifyPeer(false);
        
        $reflection = new \ReflectionClass($this->client);
        $property = $reflection->getProperty('verifyPeer');
        $property->setAccessible(true);
        
        $this->assertFalse($property->getValue($this->client));
    }

    public function testSetCertPath(): void
    {
        $certPath = '/path/to/cert.pem';
        $this->client->setCertPath($certPath);
        
        $reflection = new \ReflectionClass($this->client);
        $property = $reflection->getProperty('certPath');
        $property->setAccessible(true);
        
        $this->assertEquals($certPath, $property->getValue($this->client));
    }

    public function testSetHttpProxy(): void
    {
        $proxy = 'http://proxy.example.com:8080';
        $this->client->setHttpProxy($proxy);
        
        $reflection = new \ReflectionClass($this->client);
        $property = $reflection->getProperty('httpProxy');
        $property->setAccessible(true);
        
        $this->assertEquals($proxy, $property->getValue($this->client));
    }
} 