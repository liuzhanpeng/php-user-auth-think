<?php

namespace Lzpeng\Auth\Think\Authenticators;

use Lzpeng\Auth\Authenticators\AbstractAuthenticator;
use Lzpeng\Auth\UserInterface;
use think\Cache;
use think\Request;

/**
 * 基于\think\Cache的Token用户认证器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class TokenAuthenticator extends AbstractAuthenticator
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
     * 是否自动刷新token的过期时间
     *
     * @var boolean
     */
    protected $autoRefresh;

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

    /**
     * 扩展配置
     *
     * @var array
     */
    protected $options;

    public function __construct(
        string $tokenKey,
        int $timeout,
        bool $autoRefresh,
        Cache $cache,
        Request $request
    ) {
        $this->tokenKey = $tokenKey;
        $this->timeout = $timeout;
        $this->autoRefresh = $autoRefresh;
        $this->cache = $cache;
        $this->request = $request;
    }

    /**
     * @inheritDoc
     */
    protected function storeUser(UserInterface $user)
    {
        $package = $this->getRequestTokenPackage();

        $this->cache->set($package['userId'], $package['token'], $this->timeout);
        $this->user = $user;
    }

    /**
     * @inheritDoc
     */
    protected function loadUser()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $package = $this->getRequestTokenPackage();
        if (is_null($package)) {
            return null;
        }

        $token = $this->cache->get($package['userId']);
        if (empty($token)) {
            return null;
        }

        if ($this->autoRefresh) {
            // 更新过期时间
            $this->cache->set($package['userId'], $package['token'], $this->timeout);
        }

        return $this->getUserProvider()->findById($package['userId']);
    }

    /**
     * @inheritDoc
     */
    protected function clearUser()
    {
        $package = $this->getRequestTokenPackage();

        $this->cache->rm($package['userId']);
        $this->user = null;
    }

    /**
     * 从请求对象中查找令牌包并返回
     * 需要不同的获取方式，可直接继承类重写此方法
     *
     * @return array|null
     */
    protected function getRequestTokenPackage()
    {
        $token = $this->request->header($this->tokenKey);
        if (empty($token)) {
            return null;
        }

        $result = base64_decode($token);
        if (!$result) {
            return null;
        }

        $result = json_decode($result, true);

        return $result;
    }

    /**
     * 生成令牌包; 包含用户标识和令牌
     * 需要不同的生成方式，可直接继承类重写此方法
     *
     * @param mixed $userId 用户标识
     * @return string
     */
    protected function generateTokenPackage($userId)
    {
        $token = hash_hmac('sha256', uniqid(), $userId);

        return base64_encode(json_encode([
            'userId' => $userId,
            'token' => $token,
        ]));
    }
}
