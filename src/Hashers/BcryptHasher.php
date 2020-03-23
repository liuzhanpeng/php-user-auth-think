<?php

namespace Lzpeng\Auth\Think\Hashers;

/**
 * 基于bcrypt算法的hash处理器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class BcryptHasher implements HasherInterface
{
    /**
     * @inheritDoc
     */
    public function hash(string $value)
    {
        return password_hash($value, PASSWORD_BCRYPT);
    }

    /**
     * @inheritDoc
     */
    public function check(string $value, string $hashedValue)
    {
        return password_verify($value, $hashedValue);
    }
}
