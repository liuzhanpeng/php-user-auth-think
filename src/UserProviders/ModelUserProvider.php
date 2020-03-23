<?php

namespace Lzpeng\Auth\Think\UserProviders;

use Lzpeng\Auth\Exception\InvalidCredentialException;
use Lzpeng\Auth\Exception\Exception;
use Lzpeng\Auth\Think\Hashers\HasherInterface;
use Lzpeng\Auth\Think\PasswordInterface;
use Lzpeng\Auth\UserInterface;
use Lzpeng\Auth\UserProviderInterface;

/**
 * 基于think\Model的用户身份提供器
 * 通过用户标识/密码方式验证
 * 
 * 注意: 密码是广义的, 除了用户密码，也可示表保存到模型的验证码、token等;
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class ModelUserProvider implements UserProviderInterface
{
    /**
     * 模型类名
     *
     * @var string
     */
    protected $modelClass;

    /**
     * 模型用户标识属性名称
     * 
     * @var string
     */
    protected $idKey;

    /**
     * 用户凭证数组里的密码key
     * 
     * @var string
     */
    protected $passwordKey;

    /**
     * 哈希处理器
     *
     * @var HasherInterface
     */
    protected $hasher;

    /**
     * 构造函数
     *
     * @param string $modelClass 模型类全称
     * @param string $idKey 用于表示用户标识的属性的key
     * @param string $passwordKey 用于表示密码的属性的key; 注意: 密码是广义的, 除了用户密码，也可示表保存到模型的验证码、token等;
     * @param Lzpeng\Auth\Hasher\HasherInterface $hasher 哈希处理器
     */
    public function __construct(string $modelClass, string $idKey, string $passwordKey, HasherInterface $hasher)
    {
        $this->modelClass = $modelClass;
        $this->idKey = $idKey;
        $this->passwordKey = $passwordKey;
        $this->hasher = $hasher;
    }

    /**
     * @inheritDoc
     */
    public function findById($id)
    {
        return $this->createModel()->where($this->idKey, $id)->find();
    }

    /**
     * @inheritDoc
     */
    public function findByCredentials(array $credentials)
    {
        if (empty($credentials) || (count($credentials) === 1 && array_key_exists($this->passwordKey, $credentials))) {
            return null;
        }

        $model = $this->createModel();
        $query = $model::field('*');

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

        return $query->find();
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

        if (!$this->hasher->check($credentials[$this->passwordKey], $user->password())) {
            throw new InvalidCredentialException('密码错误');
        }
    }

    /**
     * 创建模型实例
     */
    private function createModel()
    {
        $class = '\\' . ltrim($this->modelClass, '\\');

        if (!\class_exists($class)) {
            throw new Exception(sprintf('找不到模型类[%s]', $class));
        }

        return new $class;
    }
}
