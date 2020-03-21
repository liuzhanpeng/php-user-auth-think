<?php

namespace Lzpeng\Auth\Think\Hashers;

/**
 * Null哈希处理器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class NullHasher implements HasherInterface
{
    /**
     * @inheritDoc
     */
    public function hash(string $value)
    {
        return $value;
    }

    /**
     * @inheritDoc
     */
    public function check(string $value, string $hashValue)
    {
        return strcmp($value, $hashValue) === 0;
    }
}
