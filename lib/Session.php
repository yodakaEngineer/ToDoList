<?php

class Session
{
    protected $bag;

    public function __construct($namespace = 'app')
    {
        if (!session_id()) {
            session_start();
        }

        $this->bag = &$_SESSION[$namespace];
        //$_SESSION[$namespace]がなかったら
        //$_SESSION[$namespace][app_data]を生成し
        //かつ$_SESSION[$namespace][csrf_token]がなかったら
        //そこにトークンを埋め込む
        if (!isset($this->bag)) {
            $this->bag[$this->getAppDataKey()]   = [];
            if (!$this->getCsrfToken()) {
                $this->bag[$this->getCsrfTokenKey()] = $this->generateCsrfToken();
            }
        }
    }

    public function getAppDataKey()
    {
        return 'app_data';
    }

    public function getCsrfTokenKey()
    {
        return 'csrf_token';
    }

    public function getRequestCsrfTokenKey()
    {
        return '__csrf_token';
    }

    public function generateCsrfToken()
    {
        //uniqid()は現在時刻のマイクロ秒から13文字の文字列を生成する。第一引数はプレフィックス、第二引数はtrueなら生成された文字列の最後に.を打ってさらに文字列を10文字追加する
        //脆弱性が高いので単体ではパスワードなどに使うべきではない。
        //mt_randはrandより４倍以上高速に乱数を発生させる
        //hashは第一引数のアルゴリズムで第二引数をハッシュ化する。
        return hash('sha256', uniqid(mt_rand(), true));
    }

    public function getCsrfToken()
    {
        return array_get($this->bag, $this->getCsrfTokenKey());
    }

    public function verifyCsrfToken()
    {
        //送信されてきたトークン
        $request_token = request_get($this->getRequestCsrfTokenKey());
        //$_SESSION[$namespace][csrf_token]の中のトークン
        $valid_token   = $this->getCsrfToken();

        return $request_token === $valid_token;
    }

    public function get($key, $default = null)
    {
        return array_get($this->bag[$this->getAppDataKey()], $key, $default);
    }

    public function set($key, $value)
    {
        return $this->bag[$this->getAppDataKey()][$key] = $value;
    }

    public function unset($key)
    {
        unset($this->bag[$this->getAppDataKey()][$key]);
    }

    public function unsetAll()
    {
        $this->bag[$this->getAppDataKey()] = [];
    }

    public function flash($key, $default)
    {
        $value = $this->get($key, $default);
        $this->unset($key);

        return $value;
    }
}
