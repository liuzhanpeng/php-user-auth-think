<?php

namespace Lzpeng\Auth\UserProviders;

use Lzpeng\Auth\Exception\Exception;
use Lzpeng\Auth\Exception\InvalidCredentialException;
use Lzpeng\Auth\Think\Hashers\HasherInterface;
use Lzpeng\Auth\Think\PasswordInterface;
use Lzpeng\Auth\UserInterface;
use Lzpeng\Auth\UserProviderInterface;
use Lzpeng\Auth\Users\GenericUser;
use think\Db;

/**
 * 基于think\Db的用户提供器
 * 
 * @author 刘展鹏 <liuzhanpeng@gmail.com>
 */
class DbUserProvider implements UserProviderInterface
{
    /**
     * 用户表
     *
     * @var string
     */
    private $table;

    /**
     * 用户表中的用户标识属性名称
     * 
     * @var string
     */
    private $idKey;

    /**
     * 用户凭证数组里的密码key
     * 
     * @var string
     */
    private $passwordKey;

    /**
     * hasher 
     * 
     * @var Hasher
     */
    private $hasher;

    /**
     * 构造函数
     * 
     * @param string $table 用户表
     * @param string $idKey 模型id属性名称
     * @param string $passwordKey 用户凭证数组里的密码key
     * @param bool $forceValidatePassword 是否强制验证密码
     * @param Hasher $hasher 密码hash处理器
     */
    public function __construct(
        string $table,
        string $idKey = 'id',
        string $passwordKey = 'password',
        HasherInterface $hasher
    ) {
        $this->table = $table;
        $this->idKey = $idKey;
        $this->passwordKey = $passwordKey;
        $this->hasher = $hasher;
    }

    /**
     * @inheritDoc
     */
    public function findById($id)
    {
        $result = Db::name($this->table)->where($this->idKey, $id)->find();

        if (!$result) {
            return null;
        }

        return new GenericUser($result->toArray());
    }

    /**
     * @inheritDoc
     */
    public function findByCredentials(array $credentials)
    {
        if (empty($credentials) || (count($credentials) === 1 && array_key_exists($this->passwordKey, $credentials))) {
            return null;
        }

        $query = Db::name($this->table);

        // 循环设置查询条件
        foreach ($credentials as $key => $val) {
            if ($key == $this->passwordKey) {
                continue;
            }

            if (is_array($val)) {
                $query->whereIn($key, $val);
            } else {
                $query->where($key, $val);
            }
        }

        $result =  $query->find();
        if (!$result) {
            return null;
        }

        return new GenericUser($result->toArray());
    }

    /**
     * @inheritDoc
     */
    public function validateCredentials(UserInterface $user, array $credentials)
    {
        if (!isset($credentials[$this->passwordKey])) {
            throw new InvalidCredentialException('找不密码凭证');
        }

        if (!$user instanceof PasswordInterface) {
            throw new Exception('用户身份对象必须实现PasswordInterface接口');
        }

        if (!$this->hasher->check($credentials[$this->passwordKey], $user->getPassword())) {
            throw new InvalidCredentialException('密码错误');
        }
    }
}
