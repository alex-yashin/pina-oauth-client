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
        if (empty($stateData['path'])) {
            return '';
        }

        //setcookie не поддерживает символ =
        $stateData['path'] = implode('=', $stateData['path'] ?? []);
        //на всякий случай страхуемся от того, что нам подсунули полный URL с доменом
        $stateData['path'] = parse_url($stateData['path'], PHP_URL_PATH);
        $stateData['query'] = http_build_query($stateData['query'] ?? []);

        return (!empty($stateData['path']) ? $stateData['path'] : '/') . (!empty($stateData['query']) ? '?' . $stateData['query'] : '');
    }

    public function set(string $redirectUri): string
    {
        $parsedPath = parse_url($redirectUri, PHP_URL_PATH);
        //setcookie не поддерживает символ =
        $path = explode('=', $parsedPath);

        $parsedQuery = parse_url($redirectUri, PHP_URL_QUERY);

        $query = [];
        if (!empty($parsedQuery)) {
            parse_str($parsedQuery, $query);
        }

        $stateId = $this->makeStateId();
        $stateData = [
            'path' => $path,
            'query' => $query,
        ];
        $encoded = json_encode($stateData);
        setcookie($stateId, $encoded, time() + 3600, '/');
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