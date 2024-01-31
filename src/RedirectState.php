<?php


namespace PinaOAuthClient;


class RedirectState
{

    public function get($stateId): string
    {
        if (!isset($_COOKIE[$stateId])) {
            return '';
        }

        $stateData = json_decode($_COOKIE[$stateId], true);
        if (empty($stateData['redirect_uri'])) {
            return '';
        }
        $parsedUri = parse_url($stateData['redirect_uri']);
        return (isset($parsedUri['path']) ? $parsedUri['path'] : '/') . (!empty($parsedUri['query']) ? '?' . $parsedUri['query'] : '');
    }

    public function set(string $redirectUri): string
    {
        $stateId = $this->makeStateId();
        $stateData = [
            'redirect_uri' => $redirectUri
        ];
        setcookie($stateId, json_encode($stateData), time() + 3600, '/');
        return $stateId;
    }


    protected function makeStateId(): string
    {
        if (!empty($_COOKIE['stid'])) {
            return $_COOKIE['stid'];
        }

        $hash = hash('sha256', microtime(true) . rand());
        setcookie('stid', $hash, time() + 3600, '/');
        return $hash;
    }

}