<?php

namespace Lzpeng\Auth\Think\Authenticators;

use Lzpeng\Auth\Authenticators\AbstractAuthenticator;
use Lzpeng\Auth\UserInterface;
use think\Session;

/**
 * 基于\think\Session的用户认证器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class SessionAuthenticator extends AbstractAuthenticator
{
    /**
     * 当前用户身份对象
     * 作为缓存使用
     *
     * @var UserInterface
     */
    private $user;

    /**
     * 会话key
     *
     * @var string
     */
    private $sessionKey;

    /**
     * Session对象
     *
     * @var \think\Session
     */
    private $session;

    public function __construct(string $sessionKey, Session $session)
    {
        $this->sessionKey = $sessionKey;
        $this->session = $session;
    }

    /**
     * @inheritDoc
     */
    protected function storeUser(UserInterface $user)
    {
        $this->session->set($this->sessionKey, $user->id());
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

        return $this->session->get($this->sessionKey);
    }

    /**
     * @inheritDoc
     */
    protected function clearUser()
    {
        $this->session->delete($this->sessionKey);
        $this->user = null;
    }
}
