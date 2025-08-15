<?php
/**
 * Plugin Name: E时代通行证
 * Description: 自助接入E时代通行证服务。
 * Version: 1.3.4
 * Author: MarkITwin
 * License: Mozilla
 */
 
 if (!defined('ABSPATH')) {
     exit;
 }
 
 class Emoera_Openid_Login {
     private static $instance;
     
     public static function get_instance() {
         if (self::$instance == null) {
             self::$instance = new self();
         }
         return self::$instance;
     }
     
     private function __construct() {
         add_action('admin_menu', array($this, 'add_admin_menu'));
         add_action('admin_init', array($this, 'register_settings'));
         add_action('login_form', array($this, 'add_login_button'));
         add_action('init', array($this, 'handle_oauth_callback'));
     }
     
     public function add_admin_menu() {
         add_menu_page(
            'E时代通行证接口设置',
            'E时代通行证',
            'manage_options',
            'emoera-openid-login',
            array($this, "create_settings_page"),
            'dashicons-admin-network'
            );
     }
     
     public function create_settings_page() {
         ?>
         <div class="wrap">
             <h1>E时代通行证接口设置</h1>
             <p>请在此配置接入E时代通行证所需的认证信息。</p>
             
             <form method="post" action="options.php">
                 <?php
                 settings_fields('emoera-openid-options');
                 do_settings_sections('emoera-openid-login');
                 submit_button();
                 ?>
             </form>
         </div>
        <?php
     }
     
     public function register_settings() {
         register_setting('emoera-openid-options', 'emoera-openid-client-id');
         register_setting('emoera-openid-options', 'emoera-openid-client-secret');
     
         add_settings_section(
             'emoera-openid-main-section',
             'API 认证信息',
             null,
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
     }
     
     public function render_client_id_field() {
         $value = get_option('emoera-openid-client-id');
         echo '<input type="text" name="emoera-openid-client-id" value="' . esc_attr($value) . '" class="regular-text">';
     }
     
     public function render_client_secret_field() {
         $value = get_option('emoera-openid-client-secret');
         echo '<input type="password" name="emoera-openid-client-secret" value="' . esc_attr($value) . '" class="regular-text">';
     }
     
     public function render_redirect_uri_field() {
         $redirect_uri = home_url('/?e-callback');
         echo '<input type="text" value="' . esc_attr($redirect_uri) . '" class="regular-text" readonly>';
         echo '<p class="description">请将此回调地址提供给E时代通行证的管理员进行配置。</p>';
     }
     
     public function add_login_button() {
         $client_id = get_option('emoera-openid-client-id');
         if(empty($client_id)) {
             return ;
         }
         
         $redirect_uri = urlencode(home_url('/?e-callback'));
         $state = wp_create_nonce('emoera-openid-nonce');
         set_transient('emoera-openid-state_' . $state, 'valid', 600);
         $auth_url = 'https://account.emoera.com/oauth/authorize?client_id=' . esc_attr($client_id) .
                    '&response_type=code' .
                    '&redirect_uri=' . $redirect_uri .
                    '&state=' . esc_attr($state) .
                    '&scope=read';
                    
         echo '<p class="submit" >';
         echo '<a href="' . esc_url($auth_url) . '" class="button button-primary button-large" style="width: 100%; margin-bottom: 16px; text-align: center;">' . __('使用E时代通行证登录') . '</a>';
         echo '</p>';
     }
     
     public function handle_oauth_callback() {
         if(!isset($_GET['e-callback'])) {
             return ;
         }
         if(!isset($_GET['state']) || !get_transient('emoera-openid-state_' . $_GET['state'])) {
             wp_die('无效请求：安全验证失败');
         }
         delete_transient('emoera-openid-state_' . $_GET['state']);
         if(isset($_GET['error'])) {
             wp_die('认证失败：未收到授权码(Code)');
         }
         
         $code = sanitize_text_field($_GET['code']);
         $access_token_data = $this -> get_access_token($code);
         if(is_wp_error($access_token_data)) {
             wp_die('获取访问令牌失败(Access Token)' . $access_token_data -> get_error_message());
         }
         
         $user_info = $this -> get_user_info($access_token_data['accessToken']);
         
         if(is_wp_error($user_info)) {
             wp_die('获取用户信息失败' . $user_info -> get_error_message());
         }
         
         $this -> login_or_create_user($user_info);
         
         wp_redirect(home_url());
         exit;
     }
     
     private function get_access_token($code) {
         $client_id = get_option('emoera-openid-client-id');
         $client_secret = get_option('emoera-openid-client-secret');
         $redirect_uri = home_url('/?e-callback');
         $token_url = 'https://accountapi.emoera.com/api/oauth2/token';
         
         $body = array(
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'client_id'     => $client_id,
            'client_secret' => $client_secret,
            'redirect_uri'  => $redirect_uri,
        );
        
        $response = wp_remote_post($token_url, array(
            'headers' => array('Content-Type' => 'application/json'),
            'body' => json_encode($body),
            'timeout' => 15,
        ));
        
        if(is_wp_error($response)) {
            return new WP_Error('api_error', '与令牌接口通信失败');
        }
        
        $response_body = json_decode(wp_remote_retrieve_body($response), true);
        if (!isset($response_body['data']['accessToken'])) {
            return new WP_Error('token_error', '返回的数据中未找到访问令牌(accessToken)。API返回: ' . esc_html(wp_remote_retrieve_body($response)));
        }
        return $response_body['data'];
     }
     
     private function get_user_info($access_token) {
         $client_id = get_option('emoera-openid-client-id');
         $client_secret = get_option('emoera-openid-client-secret');

        $userinfo_url = add_query_arg(array(
            'client_id'     => $client_id,
            'client_secret' => $client_secret,
            'access_token'  => $access_token,
        ), 'https://accountapi.emoera.com/api/oauth2/userinfo');
        
        $response = wp_remote_get($userinfo_url, array('timeout' => 15));
        
        if(is_wp_error($response)) {
            return new WP_Error('api_error', '与用户信息接口通信失败');
        }
        
        $response_body = json_decode(wp_remote_retrieve_body($response), true);
        
        if(!isset($response_body['data']['id'])) {
            return new WP_Error('userinfo_error', '无法解析用户信息。API返回' . esc_html(wp_remote_retrieve_body($response)));
        }
        
        return $response_body['data'];
     }
     
     private function login_or_create_user($user_data) {
         $e_user_id = $user_data['id'];
         $username = sanitize_user($user_data['username']);
         $email = isset($user_data['email']) && is_email($user_data['email']) ? sanitize_email($user_data['email']) : '';
     
         $users = get_users(array(
             'meta_key' => 'emoera-openid-user-id',
             'meta_value' => $e_user_id,
             'number' => 1,
             'count_total' => false,
         ));
     
         if(!empty($users)) {
             $user = $users[0];
         } else {
             if (!empty($email) && email_exists($email)) {
                 $user = get_user_by('email', $email);
                 update_user_meta($user -> ID, 'emoera-openid-user-id', $e_user_id);
             } else {
                 $login_name = $username;
                 if(username_exists($login_name)) {
                     $login_name = $login_name . "_" . $e_user_id;
                 }
             
             $password = wp_generate_password(24, true);
             $user_data_to_create = array(
                    'user_login' => $login_name,
                    'user_pass'  => $password,
                    'user_email' => $email,
                    'display_name' => $username,
             );
             $user_id = wp_insert_user($user_data_to_create);
             
             if(is_wp_error($user_id)) {
                 wp_die('创建新用户失败'. $user_id -> get_error_message());
             }
             
             $user = get_user_by('id', $user_id);
             update_user_meta($user_id, 'emoera-openid-user-id', $e_user_id);
             }
         }
        wp_set_current_user($user->ID, $user->user_login);
        wp_set_auth_cookie($user->ID, true);
        do_action('wp_login', $user->user_login, $user);
     }
 }
Emoera_Openid_Login::get_instance();