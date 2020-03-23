<?php

namespace Lzpeng\Auth\Think\Hashers;

class HMACHasher implements HasherInterface
{
    /**
     * 要使用的哈希算法名称，例如："md5"，"sha256"，"haval160,4" 等。
     *
     * @var string
     */
    private $algo;

    /**
     * 密钥
     *
     * @var string
     */
    private $key;

    /**
     * 构造函数
     *
     * @param string $algo 哈希算法名称
     * @param string $key 密钥
     */
    public function __construct(string $algo, string $key)
    {
        $this->algo = $algo;
        $this->key = $key;
    }

    /**
     * @inheritDoc
     */
    public function hash(string $value)
    {
        return hash_hmac($this->algo, $value, $this->key);
    }

    /**
     * @inheritDoc
     */
    public function check(string $value, string $hashValue)
    {
        $value = hash_hmac($this->algo, $value, $this->key);

        return strcmp($value, $hashValue) === 0;
    }
}
