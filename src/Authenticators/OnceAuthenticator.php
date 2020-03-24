<?php

namespace Lzpeng\Auth\Think\Authenticators;

use Lzpeng\Auth\Authenticators\AbstractAuthenticator;
use Lzpeng\Auth\UserInterface;
use think\Cache;
use think\Request;

/**
 * 一次性用户认证器
 * 登录成功后返回一个token, 在认证一次后便无效
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class OnceAuthenticator extends AbstractAuthenticator
{
    /**
     * 当前用户身份对象
     * 作为缓存使用
     *
     * @var UserInterface
     */
    private $user;

    /**
     * token名称
     * 
     * @var string
     */
    protected $tokenKey;

    /**
     * token超时时间（单位：秒 )
     *
     * @var integer
     */
    protected $timeout;

    /**
     * 缓存对象
     * 
     * @var \think\Cache;
     */
    protected $cache;

    /**
     * 请求对象
     * 
     * @var \think\Request
     */
    protected $request;

    public function __construct(string $tokenKey, int $timeout, Cache $cache, Request $request)
    {
        $this->tokenKey = $tokenKey;
        $this->timeout = $timeout;
        $this->cache = $cache;
        $this->request = $request;
    }

    /**
     * @inheritDoc
     */
    protected function storeUser(UserInterface $user)
    {
        $token = $this->generateToken($user->id());

        $this->cache->set($token, $user->id(), $this->timeout);
        $this->user = $user;

        return $token;
    }

    /**
     * @inheritDoc
     */
    protected function loadUser()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $token = $this->getRequestToken();

        if (empty($token) || !$this->cache->has($token)) {
            return null;
        }

        $userId = $this->cache->get($token);

        // 用完即弃
        $this->cache->rm($token);

        return $this->user = $this->getUserProvider()->findById($userId);
    }

    /**
     * @inheritDoc
     */
    protected function clearUser()
    {
        $token = $this->getRequestToken();

        $this->cache->rm($token);
        $this->user = null;
    }

    /**
     * 获取请求中的token
     *
     * @return string|null
     */
    private function getRequestToken()
    {
        return $this->request->get($this->tokenKey);
    }

    /**
     * 生成令牌
     *
     * @param mixed $userId 用户标识
     * @return string
     */
    private function generateToken($userId)
    {
        return hash_hmac('sha256', uniqid('', true), $userId);
    }
}
