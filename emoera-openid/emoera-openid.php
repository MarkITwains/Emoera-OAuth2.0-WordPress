<?php
/**
 * Plugin Name: E时代通行证
 * Description: 自助接入E时代通行证服务（OpenID Connect / OAuth 2.0 Authorization Code Flow + S256 PKCE + RS256 ID Token）。
 * Version: 2.0.0
 * Author: MarkITwin
 * License: Mozilla
 * Requires at least: 5.5
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * E时代通行证（E时代通行证 OpenID Connect）WordPress 登录插件。
 *
 * 本版本按《E时代通行证 OIDC 接入文档 v2.0》实现：
 * - Authorization Code Flow + S256 PKCE（PKCE 可开关）
 * - Token 端点 /api/oidc/token（application/x-www-form-urlencoded）
 * - ID Token RS256 验签（JWKS 公钥）/ HS256（client_secret）
 * - UserInfo /api/oidc/userinfo（Bearer 头）
 * - 运行时优先读取 Discovery，失败回退内置常量
 *
 * 安全要点：
 * - 算法以后台配置策略为准，绝不信任 JWT Header 自报 alg，绝不降级。
 * - state / nonce 每次随机，state 使用一次性事务（transaction）存储。
 * - code_verifier 仅存于服务端，且事务消费即删除。
 */
class Emoera_Openid_Login {

    /** 权威 Issuer（v2.0 文档与线上 Discovery 一致） */
    const ISSUER = 'https://accountapi.emoera.com/api';

    /** Discovery 文档地址 */
    const DISCOVERY_URL = 'https://accountapi.emoera.com/api/.well-known/openid-configuration';

    /** Discovery 缓存 key */
    const DISCOVERY_CACHE_KEY = 'emoera_oidc_discovery_v2';

    /** Discovery 失败回退值的短时负缓存 key */
    const DISCOVERY_FALLBACK_KEY = 'emoera_oidc_discovery_fallback_v2';

    /** JWKS 缓存 key */
    const JWKS_CACHE_KEY = 'emoera_oidc_jwks_v2';

    /** 固定 scope，必须包含 openid（OIDC 判定依据） */
    const SCOPE = 'openid profile email';

    /** HTTP 响应体大小上限：256KB */
    const MAX_RESPONSE_BYTES = 262144;

    /** 授权事务有效期（秒） */
    const TX_TTL = 600;

    /** 允许的时钟偏移（秒） */
    const CLOCK_LEEWAY = 300;

    /** @var Emoera_Openid_Login|null 单例 */
    private static $instance = null;

    /** @var array|null 请求内 Discovery 记忆缓存（避免同一次请求重复发起 HTTP） */
    private $discovery_memo = null;

    /** @var array|null 请求内 JWKS 记忆缓存（避免同一次请求重复发起 HTTP） */
    private $jwks_memo = null;

    /**
     * 获取单例。
     *
     * @return Emoera_Openid_Login
     */
    public static function get_instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * 构造函数：注册所有钩子。私有，禁止外部 new。
     */
    private function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_notices', array($this, 'admin_notices'));
        add_action('login_form', array($this, 'add_login_button'));
        add_action('init', array($this, 'handle_oauth_callback'));
        add_action('init', array($this, 'handle_fixed_login_entry'));
    }

    /* ---------------------------------------------------------------------
     * 设置读取
     * ------------------------------------------------------------------- */

    /**
     * 读取 Client ID。
     *
     * @return string
     */
    public function get_client_id() {
        $value = get_option('emoera-openid-client-id', '');
        return is_string($value) ? trim($value) : '';
    }

    /**
     * 读取 Client Secret。
     *
     * @return string
     */
    public function get_client_secret() {
        $value = get_option('emoera-openid-client-secret', '');
        return is_string($value) ? trim($value) : '';
    }

    /**
     * 回调地址（固定入口 ?e-callback，对外 URL 不变）。
     *
     * @return string
     */
    public function get_redirect_uri() {
        return home_url('/?e-callback');
    }

    /**
     * 读取 ID Token 预期签名算法策略，仅允许 RS256 / HS256，默认 RS256。
     *
     * @return string
     */
    public function get_alg_policy() {
        $value = get_option('emoera-openid-alg-policy', 'RS256');
        $value = is_string($value) ? strtoupper(trim($value)) : 'RS256';
        if ($value !== 'RS256' && $value !== 'HS256') {
            return 'RS256';
        }
        return $value;
    }

    /**
     * 是否启用 PKCE（S256），默认开启。
     *
     * @return bool
     */
    public function is_pkce_enabled() {
        $value = get_option('emoera-openid-pkce-enabled', '1');
        return (string) $value === '1';
    }

    /**
     * PHP openssl 扩展是否可用（RS256 验签依赖）。
     *
     * @return bool
     */
    public function openssl_available() {
        return function_exists('openssl_verify') && function_exists('openssl_get_publickey');
    }

    /**
     * 计算「阻止发起登录」的前置条件错误。返回空串表示可以发起。
     *
     * @return string 中文原因，多项用「；」分隔
     */
    private function get_precondition_error() {
        $issues = array();
        if ($this->get_client_id() === '') {
            $issues[] = '未配置 Client ID';
        }
        if ($this->get_client_secret() === '') {
            $issues[] = '未配置 Client Secret';
        }
        if ($this->get_alg_policy() === 'RS256' && !$this->openssl_available()) {
            $issues[] = '服务器未启用 PHP openssl 扩展，无法进行 RS256 验签';
        }
        if (empty($issues)) {
            return '';
        }
        return implode('；', $issues);
    }

    /* ---------------------------------------------------------------------
     * 后台菜单 / 设置页 / 自检面板
     * ------------------------------------------------------------------- */

    /**
     * 注册后台菜单。
     */
    public function add_admin_menu() {
        add_menu_page(
            'E时代通行证接口设置',
            'E时代通行证',
            'manage_options',
            'emoera-openid-login',
            array($this, 'create_settings_page'),
            'dashicons-admin-network'
        );
    }

    /**
     * 设置页（含连通性自检面板）。
     */
    public function create_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // 自检面板「刷新」按钮处理（独立表单，非 options.php）。
        if (isset($_POST['emoera_oidc_selfcheck_submit'])) {
            check_admin_referer('emoera_oidc_selfcheck');
            // 强制绕过缓存重新拉取 Discovery 与 JWKS。
            $this->get_discovery(true);
            $this->get_jwks(true);
            echo '<div class="notice notice-success is-dismissible"><p>已强制刷新 Discovery 与 JWKS 缓存。</p></div>';
        }

        $precondition = $this->get_precondition_error();
        ?>
        <div class="wrap">
            <h1>E时代通行证接口设置</h1>
            <p>请在此配置接入E时代通行证所需的认证信息。当前接入标准：OIDC v2.0（Authorization Code + S256 PKCE）。</p>

            <?php if ($precondition !== '') : ?>
                <div class="notice notice-error inline">
                    <p><strong>配置不完整，暂时无法发起登录：</strong><?php echo esc_html($precondition); ?></p>
                </div>
            <?php endif; ?>

            <form method="post" action="options.php">
                <?php
                settings_fields('emoera-openid-options');
                do_settings_sections('emoera-openid-login');
                submit_button();
                ?>
            </form>

            <hr>

            <?php $this->render_self_check_panel(); ?>

            <p style="margin-top:20px; font-size:14px;">
               🔗 你也可以直接访问以下地址，使用登录功能：<br>
               <code><?php echo esc_html(home_url('/?e-login')); ?></code><br>
               <a href="<?php echo esc_url(home_url('/?e-login')); ?>" target="_blank" class="button button-secondary" style="margin-top:6px;">
                    立即跳转登录功能
               </a>
            </p>
        </div>
        <?php
    }

    /**
     * 渲染「连通性自检」只读面板。
     */
    private function render_self_check_panel() {
        $discovery = $this->get_discovery();
        $source    = isset($discovery['_source']) ? (string) $discovery['_source'] : 'fallback';
        $discover_err = isset($discovery['_error']) ? (string) $discovery['_error'] : '';

        $issuer     = isset($discovery['issuer']) ? (string) $discovery['issuer'] : '';
        $auth_ep    = $this->get_endpoint('authorization_endpoint');
        $token_ep   = $this->get_endpoint('token_endpoint');
        $userinfo_ep = $this->get_endpoint('userinfo_endpoint');
        $jwks_uri   = $this->get_endpoint('jwks_uri');

        $openssl_ok = $this->openssl_available();

        // JWKS 概览
        $jwks       = $this->get_jwks();
        $jwks_error = '';
        $keys_info  = array();
        if (is_wp_error($jwks)) {
            $jwks_error = $jwks->get_error_message();
        } elseif (is_array($jwks)) {
            foreach ($jwks as $key) {
                if (!is_array($key) || !isset($key['n'])) {
                    continue;
                }
                $decoded = $this->b64url_decode((string) $key['n']);
                $bytes   = ($decoded === false) ? 0 : strlen($decoded);
                $keys_info[] = array(
                    'kid'  => isset($key['kid']) ? (string) $key['kid'] : '(无 kid)',
                    'bits' => $bytes * 8,
                );
            }
        }
        ?>
        <h2>连通性自检</h2>
        <p>以下为只读展示，用于快速定位接入问题。点击下方按钮可强制绕过缓存重新拉取 Discovery 与 JWKS。</p>

        <form method="post" action="">
            <?php wp_nonce_field('emoera_oidc_selfcheck'); ?>
            <p>
                <button type="submit" name="emoera_oidc_selfcheck_submit" value="1" class="button button-secondary">
                    刷新自检（强制重新拉取）
                </button>
            </p>
        </form>

        <table class="widefat striped" style="max-width:960px;">
            <tbody>
                <tr>
                    <td style="width:220px;"><strong>Discovery 来源</strong></td>
                    <td>
                        <?php if ($source === 'remote') : ?>
                            <span style="color:green;">线上 Discovery（已缓存 24 小时）</span>
                        <?php else : ?>
                            <span style="color:#b32d2e; font-weight:bold;">使用了内置回退值（Discovery 拉取失败）</span>
                            <?php if ($discover_err !== '') : ?>
                                <br><code><?php echo esc_html($discover_err); ?></code>
                            <?php endif; ?>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>Issuer</strong></td>
                    <td><code><?php echo esc_html($issuer); ?></code>
                        <?php if ($issuer !== self::ISSUER) : ?>
                            <span style="color:#b32d2e;">（与期望值 <?php echo esc_html(self::ISSUER); ?> 不一致）</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>授权端点</strong></td>
                    <td><code><?php echo esc_html($auth_ep); ?></code></td>
                </tr>
                <tr>
                    <td><strong>Token 端点</strong></td>
                    <td><code><?php echo esc_html($token_ep); ?></code></td>
                </tr>
                <tr>
                    <td><strong>UserInfo 端点</strong></td>
                    <td><code><?php echo esc_html($userinfo_ep); ?></code></td>
                </tr>
                <tr>
                    <td><strong>JWKS 端点</strong></td>
                    <td><code><?php echo esc_html($jwks_uri); ?></code></td>
                </tr>
                <tr>
                    <td><strong>PHP openssl 扩展</strong></td>
                    <td>
                        <?php if ($openssl_ok) : ?>
                            <span style="color:green;">可用（RS256 验签正常）</span>
                        <?php else : ?>
                            <span style="color:#b32d2e; font-weight:bold;">不可用！RS256 无法验签，必须启用 openssl 扩展或改用 HS256</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>ID Token 预期算法</strong></td>
                    <td><code><?php echo esc_html($this->get_alg_policy()); ?></code></td>
                </tr>
                <tr>
                    <td><strong>PKCE (S256)</strong></td>
                    <td><?php echo $this->is_pkce_enabled() ? '已启用' : '已关闭'; ?></td>
                </tr>
                <tr>
                    <td><strong>JWKS 密钥</strong></td>
                    <td>
                        <?php if ($jwks_error !== '') : ?>
                            <span style="color:#b32d2e;">拉取失败：<?php echo esc_html($jwks_error); ?></span>
                        <?php elseif (empty($keys_info)) : ?>
                            <span style="color:#b32d2e;">未获得任何符合要求的 RSA 签名密钥</span>
                        <?php else : ?>
                            共 <?php echo (int) count($keys_info); ?> 把通过校验的 RSA 签名公钥：
                            <ul style="margin:6px 0 0 18px;">
                                <?php foreach ($keys_info as $info) : ?>
                                    <li>kid = <code><?php echo esc_html($info['kid']); ?></code>，模数 <?php echo (int) $info['bits']; ?> bit</li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>当前回调地址</strong></td>
                    <td>
                        <code><?php echo esc_html($this->get_redirect_uri()); ?></code>
                        <p class="description">请将此地址原样提供给E时代通行证管理员登记。</p>
                    </td>
                </tr>
            </tbody>
        </table>
        <?php
    }

    /**
     * 注册设置项与字段。
     */
    public function register_settings() {
        register_setting('emoera-openid-options', 'emoera-openid-client-id', array(
            'type'              => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default'           => '',
        ));

        register_setting('emoera-openid-options', 'emoera-openid-client-secret', array(
            'type'              => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default'           => '',
        ));

        register_setting('emoera-openid-options', 'emoera-openid-pkce-enabled', array(
            'type'              => 'string',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default'           => '1',
        ));

        register_setting('emoera-openid-options', 'emoera-openid-alg-policy', array(
            'type'              => 'string',
            'sanitize_callback' => array($this, 'sanitize_alg_policy'),
            'default'           => 'RS256',
        ));

        add_settings_section(
            'emoera-openid-main-section',
            'API 认证信息',
            array($this, 'render_main_section_intro'),
            'emoera-openid-login'
        );

        add_settings_field(
            'emoera-openid-client-id',
            'Client ID',
            array($this, 'render_client_id_field'),
            'emoera-openid-login',
            'emoera-openid-main-section'
        );

        add_settings_field(
            'emoera-openid-client-secret',
            'Client Secret',
            array($this, 'render_client_secret_field'),
            'emoera-openid-login',
            'emoera-openid-main-section'
        );

        add_settings_field(
            'emoera-openid-redirect-uri',
            '回调地址 (Redirect URI)',
            array($this, 'render_redirect_uri_field'),
            'emoera-openid-login',
            'emoera-openid-main-section'
        );

        add_settings_field(
            'emoera-openid-pkce-enabled',
            '启用 PKCE (S256)',
            array($this, 'render_pkce_field'),
            'emoera-openid-login',
            'emoera-openid-main-section'
        );

        add_settings_field(
            'emoera-openid-alg-policy',
            'ID Token 预期签名算法',
            array($this, 'render_alg_field'),
            'emoera-openid-login',
            'emoera-openid-main-section'
        );
    }

    /**
     * 设置区说明文字。
     */
    public function render_main_section_intro() {
        echo '<p>这些信息由E时代通行证管理方提供。请确保回调地址已在服务方登记。</p>';
    }

    /**
     * 复选框净化：仅接受 '1' 视为开启。
     *
     * @param mixed $value 原始值
     * @return string '1' 或 '0'
     */
    public function sanitize_checkbox($value) {
        return ($value === '1' || $value === 1 || $value === true) ? '1' : '0';
    }

    /**
     * 算法策略净化：仅允许 RS256 / HS256，其余回退 RS256。
     *
     * @param mixed $value 原始值
     * @return string
     */
    public function sanitize_alg_policy($value) {
        $value = is_string($value) ? strtoupper(trim($value)) : '';
        if ($value === 'HS256') {
            return 'HS256';
        }
        return 'RS256';
    }

    /**
     * 渲染 Client ID 输入框。
     */
    public function render_client_id_field() {
        $value = $this->get_client_id();
        echo '<input type="text" name="emoera-openid-client-id" value="' . esc_attr($value) . '" class="regular-text">';
    }

    /**
     * 渲染 Client Secret 输入框。
     */
    public function render_client_secret_field() {
        $value = $this->get_client_secret();
        echo '<input type="password" name="emoera-openid-client-secret" value="' . esc_attr($value) . '" class="regular-text" autocomplete="off">';
    }

    /**
     * 渲染回调地址（只读展示，不作为选项保存）。
     */
    public function render_redirect_uri_field() {
        $redirect_uri = $this->get_redirect_uri();
        echo '<input type="text" value="' . esc_attr($redirect_uri) . '" class="regular-text" readonly>';
        echo '<p class="description">请将此回调地址提供给E时代通行证的管理员进行配置。</p>';
    }

    /**
     * 渲染 PKCE 开关。
     */
    public function render_pkce_field() {
        $enabled = $this->is_pkce_enabled();
        echo '<label>';
        // 隐藏域保证未勾选时也会提交 '0'（避免 register_setting 默认值把开关又打开）。
        echo '<input type="hidden" name="emoera-openid-pkce-enabled" value="0">';
        echo '<input type="checkbox" name="emoera-openid-pkce-enabled" value="1" ' . checked($enabled, true, false) . '>';
        echo ' 启用 Authorization Code + S256 PKCE</label>';
        echo '<p class="description">默认开启（推荐）。若服务方尚未为本客户端启用 PKCE，可关闭此项回退为普通授权码流程。</p>';
    }

    /**
     * 渲染签名算法下拉框。
     */
    public function render_alg_field() {
        $value = $this->get_alg_policy();
        echo '<select name="emoera-openid-alg-policy">';
        echo '<option value="RS256" ' . selected($value, 'RS256', false) . '>RS256（推荐，使用 JWKS 公钥验签）</option>';
        echo '<option value="HS256" ' . selected($value, 'HS256', false) . '>HS256（旧客户端兼容，使用 client_secret 验签）</option>';
        echo '</select>';
        echo '<p class="description">必须与服务方登记的算法一致。本插件严格按此策略校验，绝不自动降级。</p>';
    }

    /**
     * 后台全局提示：配置缺失或 openssl 不可用时显著告警。
     */
    public function admin_notices() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $precondition = $this->get_precondition_error();
        if ($precondition === '') {
            return;
        }
        echo '<div class="notice notice-error">';
        echo '<p><strong>E时代通行证（OpenID Connect）配置不完整，已阻止发起登录：</strong>' . esc_html($precondition) . '</p>';
        echo '<p><a class="button button-secondary" href="' . esc_url(admin_url('admin.php?page=emoera-openid-login')) . '">前往设置</a></p>';
        echo '</div>';
    }

    /* ---------------------------------------------------------------------
     * Discovery / 端点
     * ------------------------------------------------------------------- */

    /**
     * 获取 Discovery 配置。优先线上（缓存 24h），失败回退内置常量。
     *
     * @param bool $force 是否强制绕过缓存重新拉取
     * @return array 含 issuer / 各端点 / _source / _error
     */
    public function get_discovery($force = false) {
        // 请求内记忆：同一次请求只解析一次，避免设置页多次调用触发多次网络请求。
        if (!$force && is_array($this->discovery_memo)) {
            return $this->discovery_memo;
        }

        if (!$force) {
            $cached = get_transient(self::DISCOVERY_CACHE_KEY);
            if (is_array($cached) && isset($cached['issuer'])) {
                $this->discovery_memo = $cached;
                return $cached;
            }
            // 命中短时负缓存（上一次拉取失败的回退结果），直接复用，避免每次登录页加载都卡 8 秒。
            $negative = get_transient(self::DISCOVERY_FALLBACK_KEY);
            if (is_array($negative) && isset($negative['issuer'])) {
                $this->discovery_memo = $negative;
                return $negative;
            }
        }

        $fetched = $this->fetch_discovery_remote();
        if (is_array($fetched)) {
            set_transient(self::DISCOVERY_CACHE_KEY, $fetched, DAY_IN_SECONDS);
            delete_transient(self::DISCOVERY_FALLBACK_KEY);
            $this->discovery_memo = $fetched;
            return $fetched;
        }

        // 回退到内置常量，并记录失败原因供自检面板展示。
        $fallback = $this->get_fallback_discovery();
        if (is_wp_error($fetched)) {
            $fallback['_error'] = $fetched->get_error_message();
        } else {
            $fallback['_error'] = 'Discovery 返回内容无效';
        }
        // 负缓存 5 分钟：既保证面板能如实标注「使用了内置回退值」，又避免持续重试拖慢站点。
        set_transient(self::DISCOVERY_FALLBACK_KEY, $fallback, 5 * MINUTE_IN_SECONDS);
        $this->discovery_memo = $fallback;
        return $fallback;
    }

    /**
     * 拉取并校验线上 Discovery 文档。
     *
     * @return array|WP_Error
     */
    private function fetch_discovery_remote() {
        $response = wp_remote_get(self::DISCOVERY_URL, array(
            'timeout'             => 8,
            'limit_response_size' => self::MAX_RESPONSE_BYTES,
        ));

        if (is_wp_error($response)) {
            return new WP_Error('emoera_discovery_transport', '与 Discovery 端点通信失败：' . $response->get_error_message());
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        if ($status !== 200) {
            return new WP_Error('emoera_discovery_http', 'Discovery 返回 HTTP ' . $status);
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($body)) {
            return new WP_Error('emoera_discovery_json', 'Discovery 返回内容不是合法 JSON');
        }

        $issuer = isset($body['issuer']) ? (string) $body['issuer'] : '';
        if ($issuer !== self::ISSUER) {
            return new WP_Error('emoera_discovery_issuer', 'Discovery 的 issuer 不匹配：' . $issuer);
        }

        $keys = array('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri');
        foreach ($keys as $key) {
            if (empty($body[$key]) || !is_string($body[$key])) {
                return new WP_Error('emoera_discovery_missing', 'Discovery 缺少字段：' . $key);
            }
            // 所有端点必须为 https。
            if (strpos($body[$key], 'https://') !== 0) {
                return new WP_Error('emoera_discovery_scheme', 'Discovery 端点非 https：' . $key);
            }
        }

        return array(
            'issuer'                 => $issuer,
            'authorization_endpoint' => (string) $body['authorization_endpoint'],
            'token_endpoint'         => (string) $body['token_endpoint'],
            'userinfo_endpoint'      => (string) $body['userinfo_endpoint'],
            'jwks_uri'               => (string) $body['jwks_uri'],
            '_source'                => 'remote',
            '_error'                 => '',
        );
    }

    /**
     * 内置回退 Discovery（与 v2.0 文档 / 线上一致）。
     *
     * 注意：授权端点在 account.emoera.com，其余在 accountapi.emoera.com。
     *
     * @return array
     */
    private function get_fallback_discovery() {
        return array(
            'issuer'                 => self::ISSUER,
            'authorization_endpoint' => 'https://account.emoera.com/api/oauth2/authorize',
            'token_endpoint'         => 'https://accountapi.emoera.com/api/oidc/token',
            'userinfo_endpoint'      => 'https://accountapi.emoera.com/api/oidc/userinfo',
            'jwks_uri'               => 'https://accountapi.emoera.com/api/oidc/jwks',
            '_source'                => 'fallback',
            '_error'                 => '',
        );
    }

    /**
     * 读取指定端点地址。
     *
     * @param string $key 端点键名
     * @return string
     */
    private function get_endpoint($key) {
        $discovery = $this->get_discovery();
        return isset($discovery[$key]) ? (string) $discovery[$key] : '';
    }

    /**
     * 读取权威 issuer（用于 Claim 校验）。
     *
     * @return string
     */
    private function get_issuer() {
        $discovery = $this->get_discovery();
        if (isset($discovery['issuer']) && $discovery['issuer'] !== '') {
            return (string) $discovery['issuer'];
        }
        return self::ISSUER;
    }

    /* ---------------------------------------------------------------------
     * JWKS
     * ------------------------------------------------------------------- */

    /**
     * 获取 JWKS 公钥列表（已过滤）。缓存 12 小时。
     *
     * @param bool $force 是否强制重新拉取（绕过缓存）
     * @return array|WP_Error 通过校验的 JWK 数组
     */
    public function get_jwks($force = false) {
        // 请求内记忆：验签失败重试时避免同一次请求重复拉取。
        if (!$force && is_array($this->jwks_memo)) {
            return $this->jwks_memo;
        }

        if (!$force) {
            $cached = get_transient(self::JWKS_CACHE_KEY);
            if (is_array($cached)) {
                $this->jwks_memo = $cached;
                return $cached;
            }
        }

        $jwks_uri = $this->get_endpoint('jwks_uri');
        if ($jwks_uri === '') {
            return new WP_Error('emoera_jwks_no_uri', '无法确定 JWKS 端点地址');
        }

        $response = wp_remote_get($jwks_uri, array(
            'timeout'             => 8,
            'limit_response_size' => self::MAX_RESPONSE_BYTES,
        ));

        if (is_wp_error($response)) {
            return new WP_Error('emoera_jwks_transport', '与 JWKS 端点通信失败：' . $response->get_error_message());
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        if ($status !== 200) {
            return new WP_Error('emoera_jwks_http', 'JWKS 返回 HTTP ' . $status);
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($body) || !isset($body['keys']) || !is_array($body['keys'])) {
            return new WP_Error('emoera_jwks_json', 'JWKS 返回内容不是合法 JSON 或缺少 keys');
        }

        $valid = array();
        foreach ($body['keys'] as $key) {
            if (!is_array($key)) {
                continue;
            }
            // 必须为 RSA 签名公钥。
            if (!isset($key['kty']) || $key['kty'] !== 'RSA') {
                continue;
            }
            if (isset($key['use']) && $key['use'] !== 'sig') {
                continue;
            }
            if (isset($key['alg']) && $key['alg'] !== 'RS256') {
                continue;
            }
            if (empty($key['kid']) || !is_string($key['kid'])) {
                continue;
            }
            if (empty($key['n']) || empty($key['e'])) {
                continue;
            }
            $modulus = $this->b64url_decode((string) $key['n']);
            // 模数长度必须 >= 256 字节（即 >=2048 bit）。
            if ($modulus === false || strlen($modulus) < 256) {
                continue;
            }
            $valid[] = $key;
        }

        if (empty($valid)) {
            return new WP_Error('emoera_jwks_empty', 'JWKS 中没有符合要求的 RSA 签名公钥（需 kty=RSA、use=sig、alg=RS256、>=2048bit）');
        }

        set_transient(self::JWKS_CACHE_KEY, $valid, 12 * HOUR_IN_SECONDS);
        $this->jwks_memo = $valid;
        return $valid;
    }

    /**
     * 按 kid 精确选择一把公钥。
     *
     * @param string $kid 密钥 ID
     * @return array|false 命中的 JWK，未命中返回 false
     */
    private function select_jwk($kid) {
        $keys = $this->get_jwks();
        if (is_wp_error($keys) || !is_array($keys)) {
            return false;
        }
        foreach ($keys as $key) {
            if (isset($key['kid']) && hash_equals((string) $key['kid'], (string) $kid)) {
                return $key;
            }
        }
        return false;
    }

    /**
     * 获取全部通过校验的公钥（用于无 kid 时的唯一匹配）。
     *
     * @return array
     */
    private function get_valid_jwks_only() {
        $keys = $this->get_jwks();
        return is_array($keys) ? $keys : array();
    }

    /**
     * 将 JWK 转换为 PEM 公钥。失败返回 WP_Error。
     *
     * @param array $jwk JWK
     * @return string|WP_Error
     */
    private function jwk_to_pem($jwk) {
        if (!isset($jwk['n']) || !isset($jwk['e'])) {
            return new WP_Error('emoera_jwk_shape', 'JWK 缺少 n 或 e 字段');
        }
        $modulus  = $this->b64url_decode((string) $jwk['n']);
        $exponent = $this->b64url_decode((string) $jwk['e']);
        if ($modulus === false || $exponent === false || $modulus === '' || $exponent === '') {
            return new WP_Error('emoera_jwk_b64', 'JWK 的 n/e 无法 base64url 解码');
        }
        return $this->jwk_n_e_to_pem($modulus, $exponent);
    }

    /* ---------------------------------------------------------------------
     * 密码学工具
     * ------------------------------------------------------------------- */

    /**
     * base64url 解码（自动补齐 padding，允许无 padding 输入）。
     *
     * @param string $input 输入字符串
     * @return string|false 解码后的二进制，失败返回 false
     */
    private function b64url_decode($input) {
        $input = (string) $input;
        $remainder = strlen($input) % 4;
        if ($remainder !== 0) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($input, '-_', '+/'), true);
    }

    /**
     * base64url 编码（不带 padding）。
     *
     * @param string $input 原始二进制
     * @return string
     */
    private function b64url_encode($input) {
        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
    }

    /**
     * DER 长度编码。
     *
     * @param int $length 长度
     * @return string
     */
    private function der_length($length) {
        if ($length <= 0x7F) {
            return chr($length);
        }
        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * DER INTEGER 编码（有符号，首字节 >=0x80 需前置 0x00）。
     *
     * @param string $bytes 大端二进制
     * @return string
     */
    private function der_integer($bytes) {
        // 去掉多余的签名字节前导零，避免误判为负数。
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        if (ord($bytes[0]) >= 0x80) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . $this->der_length(strlen($bytes)) . $bytes;
    }

    /**
     * DER SEQUENCE 编码。
     *
     * @param string $content 内容
     * @return string
     */
    private function der_sequence($content) {
        return "\x30" . $this->der_length(strlen($content)) . $content;
    }

    /**
     * DER BIT STRING 编码（首字节 0x00 表示无未用位）。
     *
     * @param string $content 内容
     * @return string
     */
    private function der_bit_string($content) {
        return "\x03" . $this->der_length(strlen($content) + 1) . "\x00" . $content;
    }

    /**
     * 由 RSA 模数 n 与指数 e 拼装 SubjectPublicKeyInfo 并输出 PEM。
     *
     * 结构：SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }
     *
     * @param string $modulus  大端模数（二进制）
     * @param string $exponent 大端指数（二进制）
     * @return string PEM
     */
    private function jwk_n_e_to_pem($modulus, $exponent) {
        // OID 1.2.840.113549.1.1.1 (rsaEncryption)
        $oid  = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
        $null = "\x05\x00";

        $algorithm_identifier = $this->der_sequence($oid . $null);

        $rsa_public_key = $this->der_sequence(
            $this->der_integer($modulus) . $this->der_integer($exponent)
        );

        $subject_public_key_info = $this->der_sequence(
            $algorithm_identifier . $this->der_bit_string($rsa_public_key)
        );

        $pem = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= chunk_split(base64_encode($subject_public_key_info), 64, "\n");
        $pem .= "-----END PUBLIC KEY-----\n";
        return $pem;
    }

    /**
     * 解析 JWT，返回 header / payload / signature / signing_input。
     *
     * @param string $jwt JWT 字符串
     * @return array|WP_Error
     */
    private function parse_jwt($jwt) {
        if (!is_string($jwt) || $jwt === '') {
            return new WP_Error('emoera_jwt_empty', 'ID Token 为空');
        }
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return new WP_Error('emoera_jwt_shape', 'ID Token 结构非法（应为三段式 JWT）');
        }

        $header_json  = $this->b64url_decode($parts[0]);
        $payload_json = $this->b64url_decode($parts[1]);
        $signature    = $this->b64url_decode($parts[2]);

        if ($header_json === false || $payload_json === false || $signature === false) {
            return new WP_Error('emoera_jwt_b64', 'ID Token 段无法 base64url 解码');
        }

        $header  = json_decode($header_json, true);
        $payload = json_decode($payload_json, true);
        if (!is_array($header) || !is_array($payload)) {
            return new WP_Error('emoera_jwt_json', 'ID Token 的 header/payload 不是合法 JSON');
        }

        return array(
            'header'        => $header,
            'payload'       => $payload,
            'signature'     => $signature,
            'signing_input' => $parts[0] . '.' . $parts[1],
        );
    }

    /**
     * 验证 ID Token（算法策略 + 验签 + Claim 全部校验）。
     *
     * 严格按后台配置策略校验 alg，绝不降级。
     *
     * @param string $id_token ID Token
     * @param string $nonce    本次授权请求保存的 nonce
     * @return array|WP_Error 校验通过的 Claims
     */
    public function verify_id_token($id_token, $nonce) {
        $parsed = $this->parse_jwt($id_token);
        if (is_wp_error($parsed)) {
            return $parsed;
        }

        $header = $parsed['header'];
        $alg    = isset($header['alg']) ? (string) $header['alg'] : '';
        $policy = $this->get_alg_policy();

        // 关键安全点：算法必须以后台策略为准，禁止任何形式的降级。
        if ($alg !== $policy) {
            return new WP_Error(
                'emoera_alg_mismatch',
                '签名算法与后台策略不一致（策略=' . $policy . '，Token 实际=' . $alg . '），已拒绝。'
            );
        }

        if ($policy === 'RS256') {
            $verify = $this->verify_rs256($parsed);
        } else {
            $verify = $this->verify_hs256($parsed);
        }
        if (is_wp_error($verify)) {
            return $verify;
        }

        return $this->validate_claims($parsed['payload'], $nonce);
    }

    /**
     * RS256 验签：按 kid 选 JWKS 公钥，openssl_verify + SHA256。
     *
     * @param array $parsed parse_jwt 结果
     * @return true|WP_Error
     */
    private function verify_rs256($parsed) {
        if (!$this->openssl_available()) {
            return new WP_Error('emoera_no_openssl', 'PHP openssl 扩展不可用，无法进行 RS256 验签');
        }

        $kid = isset($parsed['header']['kid']) ? (string) $parsed['header']['kid'] : '';

        if ($kid === '') {
            // 未提供 kid：仅在 JWKS 中恰好存在唯一一把有效公钥时才允许匹配。
            $keys = $this->get_valid_jwks_only();
            if (count($keys) === 1) {
                $jwk = $keys[0];
            } else {
                return new WP_Error('emoera_no_kid', 'ID Token 头部缺少 kid，且 JWKS 中公钥不唯一，无法确定验签公钥');
            }
        } else {
            $jwk = $this->select_jwk($kid);
            if (!$jwk) {
                // 遇到未知 kid：强制重新拉取一次 JWKS（绕过缓存）后再试。
                $this->get_jwks(true);
                $jwk = $this->select_jwk($kid);
            }
            if (!$jwk) {
                return new WP_Error('emoera_unknown_kid', '在 JWKS 中找不到 kid = ' . $kid . ' 对应的公钥');
            }
        }

        $pem = $this->jwk_to_pem($jwk);
        if (is_wp_error($pem)) {
            return new WP_Error('emoera_pem_error', '公钥构造失败：' . $pem->get_error_message());
        }

        $result = openssl_verify($parsed['signing_input'], $parsed['signature'], $pem, OPENSSL_ALGO_SHA256);
        if ($result !== 1) {
            return new WP_Error('emoera_rs256_failed', 'ID Token RS256 验签失败（签名与公钥不匹配）');
        }
        return true;
    }

    /**
     * HS256 验签：使用 client_secret 做 HMAC-SHA256，hash_equals 恒定时间比较。
     *
     * @param array $parsed parse_jwt 结果
     * @return true|WP_Error
     */
    private function verify_hs256($parsed) {
        $secret = $this->get_client_secret();
        if ($secret === '') {
            return new WP_Error('emoera_hs_no_secret', '未配置 Client Secret，无法进行 HS256 验签');
        }
        $expected = hash_hmac('sha256', $parsed['signing_input'], $secret, true);
        if (!hash_equals($expected, $parsed['signature'])) {
            return new WP_Error('emoera_hs256_failed', 'ID Token HS256 验签失败（签名与 client_secret 不匹配）');
        }
        return true;
    }

    /**
     * 校验 ID Token Claims。
     *
     * @param array  $payload Claims
     * @param string $nonce   预期 nonce
     * @return array|WP_Error 通过则返回 Claims
     */
    private function validate_claims($payload, $nonce) {
        // iss
        $issuer = $this->get_issuer();
        if (!isset($payload['iss']) || !is_string($payload['iss']) || !hash_equals($issuer, $payload['iss'])) {
            return new WP_Error('emoera_claim_iss', 'Claim 校验失败：iss 不匹配（期望 ' . $issuer . '）');
        }

        // aud（可能是字符串或数组）
        $client_id = $this->get_client_id();
        $aud_ok    = false;
        if (isset($payload['aud'])) {
            if (is_string($payload['aud'])) {
                $aud_ok = hash_equals($client_id, $payload['aud']);
            } elseif (is_array($payload['aud'])) {
                foreach ($payload['aud'] as $aud) {
                    if (is_string($aud) && hash_equals($client_id, $aud)) {
                        $aud_ok = true;
                        break;
                    }
                }
            }
        }
        if (!$aud_ok) {
            return new WP_Error('emoera_claim_aud', 'Claim 校验失败：aud 不包含当前 Client ID');
        }

        $now    = time();
        $leeway = self::CLOCK_LEEWAY;

        // exp 未过期
        if (!isset($payload['exp'])) {
            return new WP_Error('emoera_claim_exp', 'Claim 校验失败：缺少 exp');
        }
        if ($now > ((int) $payload['exp'] + $leeway)) {
            return new WP_Error('emoera_claim_exp', 'Claim 校验失败：ID Token 已过期（exp=' . (int) $payload['exp'] . '）');
        }

        // nbf（若存在）不得生效于未来
        if (isset($payload['nbf']) && $now < ((int) $payload['nbf'] - $leeway)) {
            return new WP_Error('emoera_claim_nbf', 'Claim 校验失败：ID Token 尚未生效（nbf=' . (int) $payload['nbf'] . '）');
        }

        // iat 合理性
        if (isset($payload['iat']) && $now < ((int) $payload['iat'] - $leeway)) {
            return new WP_Error('emoera_claim_iat', 'Claim 校验失败：iat 在合理时钟偏移之外');
        }

        // nonce 必须与本次授权请求一致
        if (!isset($payload['nonce']) || !is_string($payload['nonce']) || !hash_equals((string) $nonce, $payload['nonce'])) {
            return new WP_Error('emoera_claim_nonce', 'Claim 校验失败：nonce 不匹配（重放防护）');
        }

        // sub 必须存在
        if (empty($payload['sub']) || !is_string($payload['sub'])) {
            return new WP_Error('emoera_claim_sub', 'Claim 校验失败：缺少有效的 sub');
        }

        return $payload;
    }

    /* ---------------------------------------------------------------------
     * 授权事务（state / nonce / code_verifier）
     * ------------------------------------------------------------------- */

    /**
     * 事务 transient key（对 state 做 sha256，避免 state 明文出现在选项表）。
     *
     * @param string $state state
     * @return string
     */
    private function tx_key($state) {
        return 'emoera_oidc_tx_' . hash('sha256', (string) $state);
    }

    /**
     * 生成一次性授权事务并写入 transient。
     *
     * @return array array('state' => string, 'nonce' => string, 'code_verifier' => string, 'pkce' => bool)
     */
    private function create_transaction() {
        $state    = bin2hex(random_bytes(16));
        $nonce    = bin2hex(random_bytes(16));
        $verifier = $this->generate_code_verifier();
        $pkce     = $this->is_pkce_enabled();

        $tx = array(
            'nonce'         => $nonce,
            'code_verifier' => $verifier,
            'pkce'          => $pkce,
            'created'       => time(),
        );
        set_transient($this->tx_key($state), $tx, self::TX_TTL);

        return array(
            'state'         => $state,
            'nonce'         => $nonce,
            'code_verifier' => $verifier,
            'pkce'          => $pkce,
        );
    }

    /**
     * 消费（取出并删除）一次性事务。取到即删除，防止重放。
     *
     * @param string $state state
     * @return array|false 事务数组，失败返回 false
     */
    private function consume_transaction($state) {
        if ($state === '') {
            return false;
        }
        $key = $this->tx_key($state);
        $tx  = get_transient($key);
        if (!is_array($tx)) {
            return false;
        }
        delete_transient($key);
        return $tx;
    }

    /**
     * 生成 43–128 长度的 RFC 7636 合规 code_verifier（此处长度 64）。
     *
     * 字符集：ALPHA / DIGIT / "-" / "." / "_" / "~"
     *
     * @return string
     */
    private function generate_code_verifier() {
        $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        $max     = strlen($charset) - 1;
        $out     = '';
        for ($i = 0; $i < 64; $i++) {
            $out .= $charset[random_int(0, $max)];
        }
        return $out;
    }

    /**
     * 计算 code_challenge = BASE64URL(SHA256(code_verifier))。
     *
     * @param string $verifier code_verifier
     * @return string
     */
    private function make_code_challenge($verifier) {
        return $this->b64url_encode(hash('sha256', $verifier, true));
    }

    /* ---------------------------------------------------------------------
     * 发起授权
     * ------------------------------------------------------------------- */

    /**
     * 构造授权 URL。
     *
     * @param string $state     state
     * @param string $nonce     nonce
     * @param string $verifier  code_verifier
     * @param bool   $pkce      是否启用 PKCE
     * @return string|WP_Error
     */
    private function build_authorize_url($state, $nonce, $verifier, $pkce) {
        $base = $this->get_endpoint('authorization_endpoint');
        if ($base === '') {
            return new WP_Error('emoera_no_auth_endpoint', '无法确定授权端点地址');
        }

        $params = array(
            'response_type' => 'code',
            'client_id'     => $this->get_client_id(),
            'redirect_uri'  => $this->get_redirect_uri(),
            'scope'         => self::SCOPE,
            'state'         => $state,
            'nonce'         => $nonce,
        );

        if ($pkce && $verifier !== '') {
            $params['code_challenge']        = $this->make_code_challenge($verifier);
            $params['code_challenge_method'] = 'S256';
        }

        $separator = (strpos($base, '?') === false) ? '?' : '&';
        return $base . $separator . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * 创建事务并生成授权 URL（登录按钮与固定入口共用）。
     *
     * @return string|WP_Error
     */
    private function start_authorization() {
        $precondition = $this->get_precondition_error();
        if ($precondition !== '') {
            return new WP_Error('emoera_not_configured', $precondition);
        }
        $tx = $this->create_transaction();
        return $this->build_authorize_url($tx['state'], $tx['nonce'], $tx['code_verifier'], $tx['pkce']);
    }

    /**
     * 登录页登录按钮（login_form 钩子）。
     */
    public function add_login_button() {
        if ($this->get_precondition_error() !== '') {
            return;
        }
        $auth_url = $this->start_authorization();
        if (is_wp_error($auth_url)) {
            return;
        }

        echo '<p class="submit" >';
        echo '<a href="' . esc_url($auth_url) . '" class="button button-primary button-large" style="width: 100%; margin-bottom: 16px; text-align: center;">' . esc_html__('使用E时代通行证登录') . '</a>';
        echo '</p>';
    }

    /**
     * 固定入口：访问 /?e-login 触发 302 跳转授权中心。
     */
    public function handle_fixed_login_entry() {
        if (!isset($_GET['e-login'])) {
            return;
        }

        if (is_user_logged_in()) {
            wp_die(
                '<h2 style="font-family:sans-serif;">您已登录</h2>
                <p>当前已登录账号：' . esc_html(wp_get_current_user()->display_name) . '</p>
                <p><a href="' . esc_url(home_url()) . '" class="button button-primary">返回首页</a></p>',
                '已登录',
                array('response' => 200)
            );
        }

        // 前置条件不满足时直接给出明确原因，避免回调阶段白屏。
        $precondition = $this->get_precondition_error();
        if ($precondition !== '') {
            wp_die('E时代通行证：' . esc_html($precondition) . '，无法发起登录。');
        }

        $auth_url = $this->start_authorization();
        if (is_wp_error($auth_url)) {
            wp_die('E时代通行证：无法发起登录。' . esc_html($auth_url->get_error_message()));
        }

        wp_redirect($auth_url);
        exit;
    }

    /* ---------------------------------------------------------------------
     * 回调处理
     * ------------------------------------------------------------------- */

    /**
     * 回调入口：/?e-callback（init 钩子）。
     */
    public function handle_oauth_callback() {
        if (!isset($_GET['e-callback'])) {
            return;
        }

        // state 必须存在且能命中一次性事务。
        $state = isset($_GET['state']) ? sanitize_text_field(wp_unslash($_GET['state'])) : '';
        if ($state === '') {
            wp_die('无效请求：缺少 state 参数（安全校验失败），已终止登录。');
        }

        $tx = $this->consume_transaction($state);
        if (!is_array($tx)) {
            wp_die('无效请求：state 校验失败或事务已过期（不存在 / 已使用 / 超过 10 分钟），请重新发起登录。');
        }

        // 授权端返回错误
        if (isset($_GET['error'])) {
            $error       = sanitize_text_field(wp_unslash($_GET['error']));
            $description = isset($_GET['error_description']) ? sanitize_text_field(wp_unslash($_GET['error_description'])) : '';
            wp_die('授权失败：' . esc_html($error) . ($description !== '' ? ' - ' . esc_html($description) : ''));
        }

        $code = isset($_GET['code']) ? sanitize_text_field(wp_unslash($_GET['code'])) : '';
        if ($code === '') {
            wp_die('认证失败：未收到授权码(code)。');
        }

        $verifier = isset($tx['code_verifier']) ? (string) $tx['code_verifier'] : '';
        if (!empty($tx['pkce']) && $verifier === '') {
            wp_die('内部错误：本次流程启用了 PKCE 但缺少 code_verifier，请清除站点缓存后重试。');
        }

        // 阶段一：Token 交换
        $tokens = $this->exchange_code_for_tokens($code, $verifier);
        if (is_wp_error($tokens)) {
            wp_die('【Token 交换阶段失败】' . esc_html($tokens->get_error_message()));
        }
        if (empty($tokens['id_token'])) {
            wp_die('【Token 交换阶段失败】Token 响应中缺少 id_token，无法继续。');
        }

        // 阶段二：ID Token 验证（算法策略 + 验签 + Claims）
        $nonce  = isset($tx['nonce']) ? (string) $tx['nonce'] : '';
        $claims = $this->verify_id_token($tokens['id_token'], $nonce);
        if (is_wp_error($claims)) {
            wp_die('【ID Token 验证阶段失败】' . esc_html($claims->get_error_message()));
        }

        // 阶段三：UserInfo
        $userinfo = $this->fetch_userinfo($tokens['access_token']);
        if (is_wp_error($userinfo)) {
            wp_die('【UserInfo 获取阶段失败】' . esc_html($userinfo->get_error_message()));
        }

        // sub 必须完全一致，否则拒绝创建会话。
        $userinfo_sub = isset($userinfo['sub']) ? (string) $userinfo['sub'] : '';
        $token_sub    = (string) $claims['sub'];
        if ($userinfo_sub === '' || !hash_equals($token_sub, $userinfo_sub)) {
            wp_die('【UserInfo 校验阶段失败】UserInfo 的 sub 与 ID Token 的 sub 不一致，已拒绝创建会话。');
        }

        $user_id = $this->login_or_create_user($userinfo, $token_sub);
        if (is_wp_error($user_id)) {
            wp_die('登录失败：' . esc_html($user_id->get_error_message()));
        }

        // 持久化 token，供后续调用通行证接口使用（access_token 有效期约 7199 秒）。
        $this->persist_tokens($user_id, $tokens);

        wp_redirect(home_url());
        exit;
    }

    /* ---------------------------------------------------------------------
     * API 调用
     * ------------------------------------------------------------------- */

    /**
     * 授权码换取 Token（阶段一）。
     *
     * 使用 application/x-www-form-urlencoded（client_secret_post）。
     * 响应为扁平结构，直接读取顶层 access_token。
     *
     * @param string $code     授权码
     * @param string $verifier code_verifier（未启用 PKCE 时为空串）
     * @return array|WP_Error
     */
    private function exchange_code_for_tokens($code, $verifier) {
        $token_url = $this->get_endpoint('token_endpoint');
        if ($token_url === '') {
            return new WP_Error('emoera_no_token_endpoint', '无法确定 Token 端点地址');
        }

        $body = array(
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->get_client_id(),
            'client_secret' => $this->get_client_secret(),
            'code'          => $code,
            'redirect_uri'  => $this->get_redirect_uri(),
        );
        if ($verifier !== '') {
            $body['code_verifier'] = $verifier;
        }

        // body 传数组 → wp_remote_post 自动表单编码；切勿 json_encode。
        $response = wp_remote_post($token_url, array(
            'headers' => array('Content-Type' => 'application/x-www-form-urlencoded'),
            'body'    => $body,
            'timeout' => 15,
        ));

        if (is_wp_error($response)) {
            return new WP_Error('emoera_token_transport', '与 Token 端点通信失败：' . $response->get_error_message());
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        $raw    = wp_remote_retrieve_body($response);
        $parsed = json_decode($raw, true);

        if ($status !== 200 || !is_array($parsed)) {
            $detail = is_array($parsed) ? $this->describe_oauth_error($parsed) : substr((string) $raw, 0, 300);
            return new WP_Error('emoera_token_http', 'HTTP ' . $status . ' - ' . $detail);
        }

        if (empty($parsed['access_token'])) {
            $detail = isset($parsed['error']) ? $this->describe_oauth_error($parsed) : '响应中缺少 access_token';
            return new WP_Error('emoera_token_shape', $detail);
        }

        if (empty($parsed['id_token'])) {
            return new WP_Error('emoera_token_no_idtoken', 'Token 响应中缺少 id_token（请确认 scope 含 openid）');
        }

        return array(
            'access_token'  => (string) $parsed['access_token'],
            'token_type'    => isset($parsed['token_type']) ? (string) $parsed['token_type'] : 'Bearer',
            'expires_in'    => isset($parsed['expires_in']) ? (int) $parsed['expires_in'] : 0,
            'refresh_token' => isset($parsed['refresh_token']) ? (string) $parsed['refresh_token'] : '',
            'id_token'      => (string) $parsed['id_token'],
            'scope'         => isset($parsed['scope']) ? (string) $parsed['scope'] : '',
        );
    }

    /**
     * 获取 UserInfo（阶段三）。使用 Bearer 头。
     *
     * @param string $access_token 访问令牌
     * @return array|WP_Error
     */
    private function fetch_userinfo($access_token) {
        $url = $this->get_endpoint('userinfo_endpoint');
        if ($url === '') {
            return new WP_Error('emoera_no_userinfo_endpoint', '无法确定 UserInfo 端点地址');
        }
        if ($access_token === '') {
            return new WP_Error('emoera_no_access_token', '缺少 access_token');
        }

        $response = wp_remote_get($url, array(
            'headers' => array('Authorization' => 'Bearer ' . $access_token),
            'timeout' => 15,
        ));

        if (is_wp_error($response)) {
            return new WP_Error('emoera_userinfo_transport', '与 UserInfo 端点通信失败：' . $response->get_error_message());
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        $raw    = wp_remote_retrieve_body($response);
        $parsed = json_decode($raw, true);

        if ($status !== 200 || !is_array($parsed)) {
            $detail = is_array($parsed) ? $this->describe_oauth_error($parsed) : substr((string) $raw, 0, 300);
            return new WP_Error('emoera_userinfo_http', 'HTTP ' . $status . ' - ' . $detail);
        }

        if (empty($parsed['sub'])) {
            return new WP_Error('emoera_userinfo_no_sub', 'UserInfo 响应缺少 sub 字段');
        }

        return $parsed;
    }

    /**
     * 使用 refresh_token 刷新令牌。
     *
     * @param string $refresh_token 刷新令牌
     * @return array|WP_Error 新的 token 集合
     */
    public function refresh_tokens($refresh_token) {
        if ($refresh_token === '') {
            return new WP_Error('emoera_no_refresh_token', '缺少 refresh_token');
        }
        $token_url = $this->get_endpoint('token_endpoint');
        if ($token_url === '') {
            return new WP_Error('emoera_no_token_endpoint', '无法确定 Token 端点地址');
        }

        $body = array(
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->get_client_id(),
            'client_secret' => $this->get_client_secret(),
            'refresh_token' => $refresh_token,
        );

        $response = wp_remote_post($token_url, array(
            'headers' => array('Content-Type' => 'application/x-www-form-urlencoded'),
            'body'    => $body,
            'timeout' => 15,
        ));

        if (is_wp_error($response)) {
            return new WP_Error('emoera_refresh_transport', '与 Token 端点通信失败：' . $response->get_error_message());
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        $raw    = wp_remote_retrieve_body($response);
        $parsed = json_decode($raw, true);

        if ($status !== 200 || !is_array($parsed)) {
            $detail = is_array($parsed) ? $this->describe_oauth_error($parsed) : substr((string) $raw, 0, 300);
            return new WP_Error('emoera_refresh_http', 'HTTP ' . $status . ' - ' . $detail);
        }
        if (empty($parsed['access_token'])) {
            $detail = isset($parsed['error']) ? $this->describe_oauth_error($parsed) : '响应中缺少 access_token';
            return new WP_Error('emoera_refresh_shape', $detail);
        }

        return array(
            'access_token'  => (string) $parsed['access_token'],
            'token_type'    => isset($parsed['token_type']) ? (string) $parsed['token_type'] : 'Bearer',
            'expires_in'    => isset($parsed['expires_in']) ? (int) $parsed['expires_in'] : 0,
            'refresh_token' => isset($parsed['refresh_token']) ? (string) $parsed['refresh_token'] : $refresh_token,
            'id_token'      => isset($parsed['id_token']) ? (string) $parsed['id_token'] : '',
            'scope'         => isset($parsed['scope']) ? (string) $parsed['scope'] : '',
        );
    }

    /**
     * 刷新指定用户已存储的令牌，并回写 meta。
     *
     * @param int $user_id 用户 ID
     * @return array|WP_Error
     */
    public function refresh_user_tokens($user_id) {
        $user_id = (int) $user_id;
        if ($user_id <= 0) {
            return new WP_Error('emoera_bad_user', '无效的用户 ID');
        }
        $refresh_token = get_user_meta($user_id, 'emoera-openid-refresh-token', true);
        if (!is_string($refresh_token) || $refresh_token === '') {
            return new WP_Error('emoera_no_stored_refresh_token', '该用户没有已存储的 refresh_token');
        }
        $tokens = $this->refresh_tokens($refresh_token);
        if (is_wp_error($tokens)) {
            return $tokens;
        }
        $this->persist_tokens($user_id, $tokens);
        return $tokens;
    }

    /**
     * 将 OAuth 错误对象转为可读文本。
     *
     * @param array $parsed 响应数组
     * @return string
     */
    private function describe_oauth_error($parsed) {
        $error = isset($parsed['error']) ? (string) $parsed['error'] : 'unknown_error';
        $desc  = isset($parsed['error_description']) ? (string) $parsed['error_description'] : '';
        return $error . ($desc !== '' ? ' / ' . $desc : '');
    }

    /* ---------------------------------------------------------------------
     * 用户绑定与登录
     * ------------------------------------------------------------------- */

    /**
     * 持久化令牌到用户 meta（access_token / refresh_token / 过期时间）。
     *
     * @param int   $user_id 用户 ID
     * @param array $tokens  token 集合
     */
    private function persist_tokens($user_id, $tokens) {
        $user_id = (int) $user_id;
        if ($user_id <= 0 || !is_array($tokens)) {
            return;
        }
        if (!empty($tokens['access_token'])) {
            update_user_meta($user_id, 'emoera-openid-access-token', $tokens['access_token']);
        }
        if (!empty($tokens['refresh_token'])) {
            update_user_meta($user_id, 'emoera-openid-refresh-token', $tokens['refresh_token']);
        }
        if (!empty($tokens['expires_in'])) {
            update_user_meta($user_id, 'emoera-openid-token-expires', time() + (int) $tokens['expires_in']);
        }
    }

    /**
     * 查找或创建本地用户并建立会话。
     *
     * 查找顺序：
     * 1. 按新 meta key emoera-openid-sub 命中；
     * 2. 按旧 meta key emoera-openid-user-id 命中（兼容老用户，找到后回填新 key）；
     * 3. 按邮箱绑定；
     * 4. 创建新用户。
     *
     * @param array  $userinfo UserInfo 对象
     * @param string $sub      已验签 ID Token 的 sub
     * @return int|WP_Error 用户 ID
     */
    private function login_or_create_user($userinfo, $sub) {
        $sub          = (string) $sub;
        $raw_username = isset($userinfo['username']) ? (string) $userinfo['username'] : '';
        if ($raw_username === '' && isset($userinfo['name'])) {
            $raw_username = (string) $userinfo['name'];
        }
        $email = isset($userinfo['email']) && is_email($userinfo['email'])
            ? sanitize_email($userinfo['email'])
            : '';

        if ($sub === '') {
            return new WP_Error('emoera_missing_sub', '缺少 sub，无法绑定本地账号');
        }

        // 1. 先尝试把第三方用户名转成 WP 允许的 login（严格模式）
        $login_base = sanitize_user($raw_username, true);
        $login_base = trim($login_base);

        // 2. 转完是空（中文名、特殊字符等）时用纯 ASCII 回退 login
        if ($login_base === '') {
            $login_base = 'euser_' . $sub;
        }

        // 3. 限长（WP user_login 最大 60 字符）
        if (strlen($login_base) > 60) {
            $login_base = substr($login_base, 0, 60);
        }

        $user = null;

        // 1) 新 meta key 精确绑定
        $users = get_users(array(
            'meta_key'    => 'emoera-openid-sub',
            'meta_value'  => $sub,
            'number'      => 1,
            'count_total' => false,
            'fields'      => 'all',
        ));
        if (!empty($users)) {
            $user = $users[0];
        }

        // 2) 旧 meta key 兼容（找到后回填新 key）
        if ($user === null) {
            $legacy = get_users(array(
                'meta_key'    => 'emoera-openid-user-id',
                'meta_value'  => $sub,
                'number'      => 1,
                'count_total' => false,
                'fields'      => 'all',
            ));
            if (!empty($legacy)) {
                $user = $legacy[0];
                update_user_meta($user->ID, 'emoera-openid-sub', $sub);
            }
        }

        // 3) 邮箱绑定
        if ($user === null && $email !== '' && email_exists($email)) {
            $user = get_user_by('email', $email);
            if ($user) {
                update_user_meta($user->ID, 'emoera-openid-sub', $sub);
            }
        }

        // 4) 创建新用户
        if ($user === null) {
            // 确保 login 唯一
            $login_name = $login_base;
            $counter    = 1;
            while (username_exists($login_name)) {
                $suffix     = '_' . $counter;
                $login_name = substr($login_base, 0, 60 - strlen($suffix)) . $suffix;
                $counter++;
            }

            // 显示名用原始用户名（可中文），没有就用 login
            $display_name = $raw_username !== '' ? $raw_username : $login_name;
            $password     = wp_generate_password(24, true);

            $new_user_id = wp_insert_user(array(
                'user_login'   => $login_name,
                'user_pass'    => $password,
                'user_email'   => $email,
                'display_name' => $display_name,
            ));
            if (is_wp_error($new_user_id)) {
                return new WP_Error('emoera_create_user_failed', '创建新用户失败：' . $new_user_id->get_error_message());
            }

            $user = get_user_by('id', $new_user_id);
            if (!$user) {
                return new WP_Error('emoera_load_user_failed', '创建用户后无法加载用户对象');
            }

            update_user_meta($user->ID, 'emoera-openid-sub', $sub);
            update_user_meta($user->ID, 'emoera-openid-user-id', $sub);
            update_user_meta($user->ID, 'nickname', $display_name);
        } else {
            // 已存在用户：确保新 meta key 存在
            if (get_user_meta($user->ID, 'emoera-openid-sub', true) === '') {
                update_user_meta($user->ID, 'emoera-openid-sub', $sub);
            }
        }

        // 登录
        wp_set_current_user($user->ID, $user->user_login);
        wp_set_auth_cookie($user->ID, true);
        do_action('wp_login', $user->user_login, $user);

        return (int) $user->ID;
    }
}

Emoera_Openid_Login::get_instance();
