<?php

namespace Lzpeng\Auth\Think\Hashers;

/**
 * 哈希处理器接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface HasherInterface
{
    /**
     * 将指定字符串进行哈希处理并返回
     *
     * @param string $value 待处理的字符串
     * @return string
     */
    public function hash(string $value);

    /**
     * 检查指定字符串的哈希值与给定的哈希值是否匹配
     *
     * @param string $value 待检查的字符串
     * @param string $hashValue 给定的哈希值
     * @return boolean
     */
    public function check(string $value, string $hashValue);
}
