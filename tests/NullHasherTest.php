<?php

namespace Lzpeng\Auth\Think\Tests;

use Lzpeng\Auth\Think\Hashers\NullHasher;
use PHPUnit\Framework\TestCase;

class NullHasherTest extends TestCase
{
    private $hasher;

    protected function setUp(): void
    {
        $this->hasher = new NullHasher();
    }

    public function testHash()
    {
        $hashValue = $this->hasher->hash('test');

        $this->assertTrue($this->hasher->check('test', $hashValue));
    }
}
