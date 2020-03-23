<?php

namespace Lzpeng\Auth\Think\Tests;

use Lzpeng\Auth\Think\Hashers\HMACHasher;
use PHPUnit\Framework\TestCase;

class HMACHasherTest extends TestCase
{
    private $hasher;

    protected function setUp(): void
    {
        $this->hasher = new HMACHasher('md5', 'secretkey');
    }

    public function testHash()
    {
        $hashValue = $this->hasher->hash('test');

        $this->assertTrue($this->hasher->check('test', $hashValue));
    }
}
