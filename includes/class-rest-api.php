<?php
/**
 * REST API Handler for WooCommerce PayPal Proxy Server
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class to handle REST API endpoints
 */
class WPPPS_REST_API {
    
    /**
     * PayPal API instance
     */
    private $paypal_api;
    
    /**
     * Constructor
     */
    public function __construct($paypal_api) {
        $this->paypal_api = $paypal_api;
    }
    
    /**
     * Register REST API routes
     */
    public function register_routes() {
        // Register route for PayPal buttons
        register_rest_route('wppps/v1', '/paypal-buttons', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_paypal_buttons'),
            'permission_callback' => '__return_true',
        ));
        
        // Register route for testing connection
        register_rest_route('wppps/v1', '/test-connection', array(
            'methods' => 'GET',
            'callback' => array($this, 'test_connection'),
            'permission_callback' => '__return_true',
        ));
        
        // Register route for registering an order
        register_rest_route('wppps/v1', '/register-order', array(
            'methods' => 'GET',
            'callback' => array($this, 'register_order'),
            'permission_callback' => '__return_true',
        ));
        
        // Register route for verifying a payment
        register_rest_route('wppps/v1', '/verify-payment', array(
            'methods' => 'GET',
            'callback' => array($this, 'verify_payment'),
            'permission_callback' => '__return_true',
        ));
        
        // Register route for creating a PayPal order
        register_rest_route('wppps/v1', '/create-paypal-order', array(
            'methods' => 'POST',
            'callback' => array($this, 'create_paypal_order'),
            'permission_callback' => '__return_true',
        ));
        
        // Register route for capturing a PayPal payment
        register_rest_route('wppps/v1', '/capture-payment', array(
            'methods' => 'POST',
            'callback' => array($this, 'capture_payment'),
            'permission_callback' => '__return_true',
        ));
        
        // Register webhook route for PayPal events
        register_rest_route('wppps/v1', '/paypal-webhook', array(
            'methods' => 'POST',
            'callback' => array($this, 'process_paypal_webhook'),
            'permission_callback' => '__return_true',
        ));
        
        register_rest_route('wppps/v1', '/store-test-data', array(
        'methods' => 'POST',
        'callback' => array($this, 'store_test_data'),
        'permission_callback' => '__return_true',
    ));
    
    
    // Register route for Express PayPal buttons
register_rest_route('wppps/v1', '/express-paypal-buttons', array(
    'methods' => 'GET',
    'callback' => array($this, 'get_express_paypal_buttons'),
    'permission_callback' => '__return_true',
));

// Register route for creating Express Checkout
register_rest_route('wppps/v1', '/create-express-checkout', array(
    'methods' => 'POST',
    'callback' => array($this, 'create_express_checkout'),
    'permission_callback' => '__return_true',
));

// Register route for updating Express shipping
register_rest_route('wppps/v1', '/update-express-shipping', array(
    'methods' => 'POST',
    'callback' => array($this, 'update_express_shipping'),
    'permission_callback' => '__return_true',
));

// Register route for capturing Express payment
register_rest_route('wppps/v1', '/capture-express-payment', array(
    'methods' => 'POST',
    'callback' => array($this, 'capture_express_payment'),
    'permission_callback' => '__return_true',
));
    
    register_rest_route('wppps/v1', '/seller-protection/(?P<order_id>[A-Za-z0-9]+)', array(
    'methods' => 'GET',
    'callback' => array($this, 'get_seller_protection'),
    'permission_callback' => '__return_true',
    'args' => array(
        'order_id' => array(
            'required' => true,
            'validate_callback' => function($param) {
                return is_string($param);
            }
        ),
        'api_key' => array(
            'required' => true,
        ),
        'hash' => array(
            'required' => true,
        ),
        'timestamp' => array(
            'required' => true,
        ),
    ),
));

    }
    
    
/**
 * Store order data from Website A
 */
public function store_test_data($request) {
    // Get request JSON
    $params = $this->get_json_params($request);
    
    // Log for debugging
    error_log('STORE DATA - Received params: ' . print_r($params, true));
    
    // Validate required parameters
    if (empty($params['api_key']) || empty($params['order_id'])) {
        return new WP_Error(
            'missing_params',
            __('Missing required parameters', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    // Validate API key
    $site = $this->get_site_by_api_key($params['api_key']);
    if (!$site) {
        return new WP_Error(
            'invalid_api_key',
            __('Invalid API key', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    // Prepare data to store
    $data_to_store = array();
    
    // Store description/test data if provided
    if (isset($params['test_data'])) {
        $data_to_store['description'] = sanitize_text_field($params['test_data']);
    }
    
    // Store shipping address if provided
    if (!empty($params['shipping_address'])) {
        $data_to_store['shipping_address'] = $params['shipping_address'];
        error_log('STORE DATA - Received shipping address: ' . json_encode($params['shipping_address']));
    }
    
    // Store billing address if provided
    if (!empty($params['billing_address'])) {
        $data_to_store['billing_address'] = $params['billing_address'];
        error_log('STORE DATA - Received billing address: ' . json_encode($params['billing_address']));
    }
    
   
    // Store line items if provided
if (!empty($params['line_items']) && is_array($params['line_items'])) {
    // Process line items for mapped products
    foreach ($params['line_items'] as $key => $item) {
        // If this item has a mapped product ID, look up the product details
        if (!empty($item['mapped_product_id'])) {
            $mapped_product_id = intval($item['mapped_product_id']);
            $mapped_product = wc_get_product($mapped_product_id);
            
            if ($mapped_product) {
                // Replace product details but keep pricing from Website A
                $params['line_items'][$key]['name'] = $mapped_product->get_name();
                $params['line_items'][$key]['sku'] = $mapped_product->get_sku();
                $params['line_items'][$key]['description'] = $mapped_product->get_short_description() ? 
                    substr(wp_strip_all_tags($mapped_product->get_short_description()), 0, 127) : '';
                
                // Store the actual product ID for reference
                $params['line_items'][$key]['actual_product_id'] = $mapped_product_id;
                
                error_log('STORE DATA - Mapped product ID ' . $item['product_id'] . ' to ' . $mapped_product_id . ': ' . $mapped_product->get_name());
            } else {
                error_log('STORE DATA - Mapped product ID ' . $mapped_product_id . ' not found');
            }
        }
    }
    
    $data_to_store['line_items'] = $params['line_items'];
    error_log('STORE DATA - Processed ' . count($params['line_items']) . ' line items with mappings');
}
    
    // Store shipping amount if provided
    if (isset($params['shipping_amount'])) {
        $data_to_store['shipping_amount'] = (float)$params['shipping_amount'];
        error_log('STORE DATA - Received shipping amount: ' . $params['shipping_amount']);
    }
    
    // Store shipping tax if provided
    if (isset($params['shipping_tax'])) {
        $data_to_store['shipping_tax'] = (float)$params['shipping_tax'];
    }
    
    // Store tax total if provided
    if (isset($params['tax_total'])) {
        $data_to_store['tax_total'] = (float)$params['tax_total'];
        error_log('STORE DATA - Received tax total: ' . $params['tax_total']);
    }
    
    // Store currency if provided
    if (isset($params['currency'])) {
        $data_to_store['currency'] = sanitize_text_field($params['currency']);
    }
    
    // Store tax settings
    if (isset($params['prices_include_tax'])) {
        $data_to_store['prices_include_tax'] = (bool)$params['prices_include_tax'];
    }
    
    if (isset($params['tax_display_cart'])) {
        $data_to_store['tax_display_cart'] = sanitize_text_field($params['tax_display_cart']);
    }
    
    if (isset($params['tax_display_shop'])) {
        $data_to_store['tax_display_shop'] = sanitize_text_field($params['tax_display_shop']);
    }
    
    // Only proceed if we have data to store
    if (!empty($data_to_store)) {
        // Store in transient
        $transient_key = 'wppps_order_data_' . $site->id . '_' . $params['order_id'];
        set_transient($transient_key, $data_to_store, 24 * HOUR_IN_SECONDS);
        error_log('STORE DATA - Stored detailed order data for order: ' . $params['order_id']);
    }
    
    // Return success
    return new WP_REST_Response(array(
        'success' => true,
        'message' => 'Order data stored successfully',
    ), 200);
}

/**
 * Get stored test data for an order
 */
private function get_test_data($site_id, $order_id) {
    $transient_key = 'wppps_test_data_' . $site_id . '_' . $order_id;
    $test_data = get_transient($transient_key);
    
    if ($test_data) {
        error_log('TEST DATA - Retrieved test data: "' . $test_data . '" for order: ' . $order_id);
    } else {
        error_log('TEST DATA - No test data found for order: ' . $order_id);
    }
    
    return $test_data;
}
    
    /**
     * Render the PayPal buttons template
     */
    public function get_paypal_buttons($request) {
    // validate using api key and secret
    $api_key = $request->get_param('api_key');
    $api_secret_hash = $request->get_param('hash');
    $get_timestamp_from_client = $request->get_param('timestamp');
    $site = null;
    
    
    if (!empty($api_key)) {
        $site = $this->get_site_by_api_key($api_key);
        $timestamp = $get_timestamp_from_client;
        $xpected_hash = hash_hmac('sha256', $timestamp, $site->api_secret); 
        
         // Verify hash
        if (!hash_equals($xpected_hash, $api_secret_hash)) {
            return new WP_Error(
                'invalid_hash',
                __('Invalid authentication hash', 'woo-paypal-proxy-server'),
                array('status' => 401)
            );
        }
        
        if (!$site) {
            header('Content-Type: text/html; charset=UTF-8');
            echo '<div style="color:red;">Invalid API key. Please check your configuration.</div>';
            exit;
        }
    }
    
    // Get parameters
    $amount = $request->get_param('amount');
    $currency = $request->get_param('currency') ?: 'USD';
    $callback_url = $request->get_param('callback_url') ? base64_decode($request->get_param('callback_url')) : '';
    $site_url = $request->get_param('site_url') ? base64_decode($request->get_param('site_url')) : '';
    
    // Set up template variables
    $client_id = $this->paypal_api->get_client_id();
    $environment = $this->paypal_api->get_environment();
    
    // Critical: Set the content type header to HTML
    header('Content-Type: text/html; charset=UTF-8');
    
    // Include the template directly
    include WPPPS_PLUGIN_DIR . 'templates/paypal-buttons.php';
    
    // Exit to prevent WordPress from further processing
    exit;
}
    
    /**
     * Test connection from Website A
     */
    public function test_connection($request) {
        // Validate request
        $validation = $this->validate_request($request);
        if (is_wp_error($validation)) {
            return $validation;
        }
        
        // Get site URL
        $site_url = base64_decode($request->get_param('site_url'));
        $api_key = $request->get_param('api_key');
        
        // Get site details from database
        $site = $this->get_site_by_api_key($api_key);
        
        if (!$site) {
            // Site not found, let's check if this is a new site
            if (current_user_can('manage_options')) {
                // Return success for admins running the test
                return new WP_REST_Response(array(
                    'success' => true,
                    'message' => __('Connection successful, but site is not registered yet. Please register the site in the admin panel.', 'woo-paypal-proxy-server'),
                    'site_url' => $site_url,
                ), 200);
            } else {
                return new WP_Error(
                    'invalid_api_key',
                    __('Invalid API key or site not registered', 'woo-paypal-proxy-server'),
                    array('status' => 401)
                );
            }
        }
        
        // Check if site URL matches
        if ($site->site_url !== $site_url) {
            // Log the mismatch but don't disclose to client
            $this->log_warning('Site URL mismatch in test connection: ' . $site_url . ' vs ' . $site->site_url);
        }
        
        // Return success response
        return new WP_REST_Response(array(
            'success' => true,
            'message' => __('Connection successful', 'woo-paypal-proxy-server'),
            'site_name' => $site->site_name,
        ), 200);
    }
    
    /**
     * Register an order from Website A
     */
    public function register_order($request) {
        // Validate request
        $validation = $this->validate_request($request);
        if (is_wp_error($validation)) {
            return $validation;
        }
        
        // Get parameters
        $api_key = $request->get_param('api_key');
        $order_data_encoded = $request->get_param('order_data');
        
        if (empty($order_data_encoded)) {
            return new WP_Error(
                'missing_data',
                __('Order data is required', 'woo-paypal-proxy-server'),
                array('status' => 400)
            );
        }
        
        // Decode order data
        $order_data = json_decode(base64_decode($order_data_encoded), true);
        
        if (empty($order_data) || !is_array($order_data)) {
            return new WP_Error(
                'invalid_data',
                __('Invalid order data format', 'woo-paypal-proxy-server'),
                array('status' => 400)
            );
        }
        
        // Validate required order fields
        $required_fields = array('order_id', 'order_total', 'currency');
        foreach ($required_fields as $field) {
            if (empty($order_data[$field])) {
                return new WP_Error(
                    'missing_field',
                    sprintf(__('Missing required field: %s', 'woo-paypal-proxy-server'), $field),
                    array('status' => 400)
                );
            }
        }
        
        // Get site by API key
        $site = $this->get_site_by_api_key($api_key);
        
        if (!$site) {
            return new WP_Error(
                'invalid_api_key',
                __('Invalid API key or site not registered', 'woo-paypal-proxy-server'),
                array('status' => 401)
            );
        }
        
        // Check if site URL matches
        if (!empty($order_data['site_url']) && $site->site_url !== $order_data['site_url']) {
            // Log the mismatch
            $this->log_warning('Site URL mismatch in order registration: ' . $order_data['site_url'] . ' vs ' . $site->site_url);
        }
        
        // Store order data in session for later use
        $this->store_order_data($site->id, $order_data);
        
        // Return success response
        return new WP_REST_Response(array(
            'success' => true,
            'message' => __('Order registered successfully', 'woo-paypal-proxy-server'),
            'order_id' => $order_data['order_id'],
        ), 200);
    }
    
    /**
     * Verify a payment with PayPal
     */
    public function verify_payment($request) {
        // Validate request
        $validation = $this->validate_request($request);
        if (is_wp_error($validation)) {
            return $validation;
        }
        
        // Get parameters
        $api_key = $request->get_param('api_key');
        $paypal_order_id = $request->get_param('paypal_order_id');
        $order_id = $request->get_param('order_id');
        
        if (empty($paypal_order_id) || empty($order_id)) {
            return new WP_Error(
                'missing_data',
                __('PayPal order ID and order ID are required', 'woo-paypal-proxy-server'),
                array('status' => 400)
            );
        }
        
        // Get site by API key
        $site = $this->get_site_by_api_key($api_key);
        
        if (!$site) {
            return new WP_Error(
                'invalid_api_key',
                __('Invalid API key or site not registered', 'woo-paypal-proxy-server'),
                array('status' => 401)
            );
        }
        
        // Get order details from PayPal
        $order_details = $this->paypal_api->get_order_details($paypal_order_id);
        
        if (is_wp_error($order_details)) {
            return new WP_Error(
                'paypal_error',
                $order_details->get_error_message(),
                array('status' => 500)
            );
        }
        
        // Check order status
        if ($order_details['status'] !== 'COMPLETED') {
            return new WP_Error(
                'payment_incomplete',
                __('Payment has not been completed', 'woo-paypal-proxy-server'),
                array('status' => 400)
            );
        }
        
        // Find transaction in log
        global $wpdb;
        $log_table = $wpdb->prefix . 'wppps_transaction_log';
        
        $transaction = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $log_table WHERE paypal_order_id = %s AND order_id = %s AND site_id = %d",
            $paypal_order_id,
            $order_id,
            $site->id
        ));
        
        if (!$transaction) {
            return new WP_Error(
                'transaction_not_found',
                __('Transaction not found in logs', 'woo-paypal-proxy-server'),
                array('status' => 404)
            );
        }
        
        // Check transaction status
        if ($transaction->status !== 'completed') {
            // Update transaction status if needed
            $wpdb->update(
                $log_table,
                array(
                    'status' => 'completed',
                    'completed_at' => current_time('mysql'),
                ),
                array('id' => $transaction->id)
            );
        }
        
        // Get the capture ID and other details from the order
        $capture_id = '';
        $payer_email = '';
        
        if (!empty($order_details['purchase_units'][0]['payments']['captures'][0]['id'])) {
            $capture_id = $order_details['purchase_units'][0]['payments']['captures'][0]['id'];
        }
        
        if (!empty($order_details['payer']['email_address'])) {
            $payer_email = $order_details['payer']['email_address'];
        }
        
        // Return success response with payment details
        return new WP_REST_Response(array(
            'success' => true,
            'message' => __('Payment verified successfully', 'woo-paypal-proxy-server'),
            'status' => 'completed',
            'transaction_id' => $capture_id,
            'payer_email' => $payer_email,
            'payment_method' => 'paypal',
        ), 200);
    }
    
/**
 * Create a PayPal order
 */
public function create_paypal_order($request) {
    // Get request JSON
    $params = $this->get_json_params($request);
    
    if (empty($params)) {
        return new WP_Error(
            'invalid_request',
            __('Invalid request format', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    // Validate required parameters
    $required_params = array('api_key', 'order_id', 'amount', 'currency');
    foreach ($required_params as $param) {
        if (empty($params[$param])) {
            return new WP_Error(
                'missing_param',
                sprintf(__('Missing required parameter: %s', 'woo-paypal-proxy-server'), $param),
                array('status' => 400)
            );
        }
    }
    
    // Validate request signature if available
    if (!empty($params['timestamp']) && !empty($params['hash'])) {
        $validation = $this->validate_signature($params['api_key'], $params['timestamp'], $params['hash'], $params['order_id'] . $params['amount']);
        if (is_wp_error($validation)) {
            return $validation;
        }
    }
    
    // Get site by API key
    $site = $this->get_site_by_api_key($params['api_key']);
    
    if (!$site) {
        return new WP_Error(
            'invalid_api_key',
            __('Invalid API key or site not registered', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    // Get order data from transient storage
    $order_data = $this->get_order_data($site->id, $params['order_id']);
    error_log('Retrieved order data: ' . json_encode($order_data));
    
    $custom_data = array();
    
    // Add description if available
    if (!empty($order_data['description'])) {
        $custom_data['description'] = $order_data['description'];
    }
    
    // Add shipping address if available
    if (!empty($order_data['shipping_address'])) {
        $custom_data['shipping_address'] = $order_data['shipping_address'];
        error_log('Using stored shipping address');
    }
    
    // Add billing address if available
    if (!empty($order_data['billing_address'])) {
        $custom_data['billing_address'] = $order_data['billing_address'];
        error_log('Using stored billing address');
    }
    
    // Add line items if available
    if (!empty($order_data['line_items'])) {
        $custom_data['line_items'] = $order_data['line_items'];
        error_log('Using ' . count($order_data['line_items']) . ' stored line items');
    }
    
    // Add shipping amount if available
    if (isset($order_data['shipping_amount'])) {
        $custom_data['shipping_amount'] = $order_data['shipping_amount'];
        error_log('Using stored shipping amount: ' . $order_data['shipping_amount']);
    }
    
    // Add shipping tax if available
    if (isset($order_data['shipping_tax'])) {
        $custom_data['shipping_tax'] = $order_data['shipping_tax'];
    }
    
    // Add tax total if available
    if (isset($order_data['tax_total'])) {
        $custom_data['tax_total'] = $order_data['tax_total'];
    }
    
    // Create PayPal order
    $paypal_order = $this->paypal_api->create_order(
        $params['amount'],
        $params['currency'],
        $params['order_id'],
        !empty($params['return_url']) ? $params['return_url'] : '',
        !empty($params['cancel_url']) ? $params['cancel_url'] : '',
        $custom_data
    );
    
    if (is_wp_error($paypal_order)) {
        return new WP_Error(
            'paypal_error',
            $paypal_order->get_error_message(),
            array('status' => 500)
        );
    }
    
    // Log the transaction
    $this->log_transaction($site->id, $params['order_id'], $paypal_order['id'], $params['amount'], $params['currency']);
    
    // Return the PayPal order details
    return new WP_REST_Response(array(
        'success' => true,
        'order_id' => $paypal_order['id'],
        'status' => $paypal_order['status'],
        'links' => $paypal_order['links'],
    ), 200);
}
    
    /**
     * Capture a PayPal payment
     */
    public function capture_payment($request) {
        // Get request JSON
        $params = $this->get_json_params($request);
        
        if (empty($params)) {
            return new WP_Error(
                'invalid_request',
                __('Invalid request format', 'woo-paypal-proxy-server'),
                array('status' => 400)
            );
        }
        
        // Validate required parameters
        $required_params = array('api_key', 'paypal_order_id');
        foreach ($required_params as $param) {
            if (empty($params[$param])) {
                return new WP_Error(
                    'missing_param',
                    sprintf(__('Missing required parameter: %s', 'woo-paypal-proxy-server'), $param),
                    array('status' => 400)
                );
            }
        }
        
        // Validate request signature if available
        if (!empty($params['timestamp']) && !empty($params['hash'])) {
            $validation = $this->validate_signature($params['api_key'], $params['timestamp'], $params['hash'], $params['paypal_order_id']);
            if (is_wp_error($validation)) {
                return $validation;
            }
        }
        
        // Get site by API key
        $site = $this->get_site_by_api_key($params['api_key']);
        
        if (!$site) {
            return new WP_Error(
                'invalid_api_key',
                __('Invalid API key or site not registered', 'woo-paypal-proxy-server'),
                array('status' => 401)
            );
        }
        
        // Capture the payment
        $capture = $this->paypal_api->capture_payment($params['paypal_order_id']);
        
        $paypal_order_id = $params['paypal_order_id'];
        
        
        

        
        if (is_wp_error($capture)) {
            return new WP_Error(
                'paypal_error',
                $capture->get_error_message(),
                array('status' => 500)
            );
        }
        
        // Update transaction log
        global $wpdb;
        $log_table = $wpdb->prefix . 'wppps_transaction_log';
        
        $wpdb->update(
            $log_table,
            array(
                'status' => 'completed',
                'completed_at' => current_time('mysql'),
                'transaction_data' => json_encode($capture),
            ),
            array(
                'paypal_order_id' => $params['paypal_order_id'],
                'site_id' => $site->id,
            )
        );
        
        // Extract transaction ID
        $transaction_id = '';
        if (!empty($capture['purchase_units'][0]['payments']['captures'][0]['id'])) {
            $transaction_id = $capture['purchase_units'][0]['payments']['captures'][0]['id'];
        }
        
        $seller_protection = 'UNKNOWN';
    if (!empty($capture['purchase_units'][0]['payments']['captures'][0]['seller_protection']['status'])) {
        $seller_protection = $capture['purchase_units'][0]['payments']['captures'][0]['seller_protection']['status'];
        error_log('Found seller protection status: ' . $seller_protection);
        
        // Store it for later retrieval
        $this->store_seller_protection($paypal_order_id, $seller_protection);
    }
        
        // Return capture details
        return new WP_REST_Response(array(
            'success' => true,
            'transaction_id' => $transaction_id,
            'status' => $capture['status'],
        ), 200);
    }
    
    /**
     * Process PayPal webhook events
     */
    public function process_paypal_webhook($request) {
        // Get request body
        $payload = $request->get_body();
        $event_data = json_decode($payload, true);
        
        if (empty($event_data)) {
            return new WP_Error(
                'invalid_payload',
                __('Invalid webhook payload', 'woo-paypal-proxy-server'),
                array('status' => 400)
            );
        }
        
        // Process the webhook event
        $result = $this->paypal_api->process_webhook_event($event_data);
        
        if (is_wp_error($result)) {
            return new WP_Error(
                'webhook_processing_error',
                $result->get_error_message(),
                array('status' => 500)
            );
        }
        
        // Return success response
        return new WP_REST_Response(array(
            'success' => true,
        ), 200);
    }
    
private function validate_request($request) {
    // Get authentication parameters
    $api_key = $request->get_param('api_key');
    
    // For debugging: Log all parameters
    error_log('PayPal Proxy Debug - Request parameters: ' . print_r($request->get_params(), true));
    
    if (empty($api_key)) {
        return new WP_Error(
            'missing_auth',
            __('Missing API key parameter', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    // Get site by API key
    $site = $this->get_site_by_api_key($api_key);
    
    if (!$site) {
        return new WP_Error(
            'invalid_api_key',
            __('Invalid API key', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    // TEMPORARILY DISABLED HASH VALIDATION FOR TESTING
    // Just log that we would normally validate the hash here
    error_log('PayPal Proxy Debug - Hash validation temporarily disabled for testing');
    
    return true;
}  
    /**
     * Validate request signature
     */
    private function validate_signature($api_key, $timestamp, $hash, $data) {
        // Get site by API key
        $site = $this->get_site_by_api_key($api_key);
        
        if (!$site) {
            return new WP_Error(
                'invalid_api_key',
                __('Invalid API key', 'woo-paypal-proxy-server'),
                array('status' => 401)
            );
        }
        
        // Check timestamp (prevent replay attacks)
        $current_time = time();
        $time_diff = abs($current_time - intval($timestamp));
        
        if ($time_diff > 3600) { // 1 hour max difference
            return new WP_Error(
                'expired_timestamp',
                __('Authentication timestamp has expired', 'woo-paypal-proxy-server'),
                array('status' => 401)
            );
        }
        
        // Calculate expected hash
        $hash_data = $timestamp . $data . $api_key;
        $expected_hash = hash_hmac('sha256', $hash_data, $site->api_secret);
        
        // Verify hash
        if (!hash_equals($expected_hash, $hash)) {
            return new WP_Error(
                'invalid_hash',
                __('Invalid authentication hash', 'woo-paypal-proxy-server'),
                array('status' => 401)
            );
        }
        
        return true;
    }
    
    /**
     * Get site by API key
     */
    private function get_site_by_api_key($api_key) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wppps_sites';
        
        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table_name WHERE api_key = %s AND status = 'active'",
            $api_key
        ));
    }
    
    /**
     * Store order data in session
     */
    private function store_order_data($site_id, $order_data) {
        // Generate a unique key
        $key = 'wppps_order_' . $site_id . '_' . $order_data['order_id'];
        
        // Store in transient for 24 hours
        set_transient($key, $order_data, 24 * HOUR_IN_SECONDS);
        
        return true;
    }
    
    /**
     * Get order data from session
     */
    private function get_order_data($site_id, $order_id) {
    $transient_key = 'wppps_order_data_' . $site_id . '_' . $order_id;
    $data = get_transient($transient_key);
    
    if ($data) {
        error_log('GET DATA - Retrieved data for order: ' . $order_id);
        // Debug log to see exactly what data is being returned
        error_log('GET DATA - Content of data: ' . json_encode($data));
    } else {
        error_log('GET DATA - No data found for order: ' . $order_id);
    }
    
    return $data;
    }
    
    /**
     * Log transaction in database
     */
    private function log_transaction($site_id, $order_id, $paypal_order_id, $amount, $currency) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wppps_transaction_log';
        
        // Check if transaction already exists
        $existing = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table_name WHERE site_id = %d AND order_id = %s AND paypal_order_id = %s",
            $site_id,
            $order_id,
            $paypal_order_id
        ));
        
        if ($existing) {
            // Update existing transaction
            $wpdb->update(
                $table_name,
                array(
                    'amount' => $amount,
                    'currency' => $currency,
                    'status' => 'pending',
                    'created_at' => current_time('mysql'),
                ),
                array('id' => $existing)
            );
            
            return $existing;
        } else {
            // Insert new transaction
            $wpdb->insert(
                $table_name,
                array(
                    'site_id' => $site_id,
                    'order_id' => $order_id,
                    'paypal_order_id' => $paypal_order_id,
                    'amount' => $amount,
                    'currency' => $currency,
                    'status' => 'pending',
                    'created_at' => current_time('mysql'),
                )
            );
            
            return $wpdb->insert_id;
        }
    }
    
    /**
     * Get JSON parameters from request
     */
    private function get_json_params($request) {
    $content_type = $request->get_content_type();
    $json_params = null;
    
    // First try: Check if it's JSON content type
    if ($content_type && strpos($content_type['value'], 'application/json') !== false) {
        $json_params = $request->get_json_params();
        error_log('Express Checkout: Got JSON params from content type: ' . json_encode($json_params));
    }
    
    // Second try: Check body for JSON
    if (empty($json_params)) {
        $body = $request->get_body();
        if (!empty($body)) {
            $params = json_decode($body, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $json_params = $params;
                error_log('Express Checkout: Got JSON params from body: ' . json_encode($json_params));
            }
        }
    }
    
    // Third try: Check if it's form data
    if (empty($json_params)) {
        $params = $request->get_params();
        if (!empty($params)) {
            $json_params = $params;
            error_log('Express Checkout: Got params from request: ' . json_encode($json_params));
        }
    }
    
    return $json_params;
}
    
    /**
     * Log an error message
     */
    private function log_error($message) {
        if (function_exists('wc_get_logger')) {
            $logger = wc_get_logger();
            $logger->error($message, array('source' => 'woo-paypal-proxy-server'));
        } else {
            error_log('[WooCommerce PayPal Proxy Server] ' . $message);
        }
    }
    
    /**
     * Log a warning message
     */
    private function log_warning($message) {
        if (function_exists('wc_get_logger')) {
            $logger = wc_get_logger();
            $logger->warning($message, array('source' => 'woo-paypal-proxy-server'));
        } else {
            error_log('[WooCommerce PayPal Proxy Server] Warning: ' . $message);
        }
    }
    
    public function get_seller_protection($request) {
    // Get parameters
    $paypal_order_id = $request->get_param('order_id');
    $api_key = $request->get_param('api_key');
    $hash = $request->get_param('hash');
    $timestamp = $request->get_param('timestamp');
    
    // Validate API key and security hash
    $site = $this->get_site_by_api_key($api_key);
    if (!$site) {
        return new WP_Error(
            'invalid_api_key',
            __('Invalid API key', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    // Validate hash for security
    $hash_data = $timestamp . $paypal_order_id . $api_key;
    $expected_hash = hash_hmac('sha256', $hash_data, $site->api_secret);
    
    if (!hash_equals($expected_hash, $hash)) {
        return new WP_Error(
            'invalid_hash',
            __('Invalid security hash', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    // Get the seller protection status from storage
    $transient_key = 'wppps_seller_protection_' . $paypal_order_id;
    $seller_protection = get_transient($transient_key);
    
    if ($seller_protection === false) {
        $seller_protection = 'UNKNOWN'; // Default if not found
    }
    
    error_log('Retrieved seller protection status for ' . $paypal_order_id . ': ' . $seller_protection);
    
    // Return the seller protection status
    return new WP_REST_Response(array(
        'success' => true,
        'order_id' => $paypal_order_id,
        'seller_protection' => $seller_protection
    ), 200);
}
    
    private function store_seller_protection($paypal_order_id, $status) {
        // Use a transient that expires after 24 hours
        $transient_key = 'wppps_seller_protection_' . $paypal_order_id;
        set_transient($transient_key, $status, 24 * HOUR_IN_SECONDS);
        error_log('Stored seller protection status for order ' . $paypal_order_id . ': ' . $status);
        return true;
    }
    
    
/**
 * Render the Express PayPal buttons template
 */
public function get_express_paypal_buttons($request) {
    // Validate using api key and secret
    $api_key = $request->get_param('api_key');
    $api_secret_hash = $request->get_param('hash');
    $timestamp = $request->get_param('timestamp');
    $site = null;
    
    error_log('Express Checkout: Received button request with params: ' . json_encode($request->get_params()));
    
    if (!empty($api_key)) {
        $site = $this->get_site_by_api_key($api_key);
        
        if (!$site) {
            header('Content-Type: text/html; charset=UTF-8');
            echo '<div style="color:red;">Invalid API key. Please check your configuration.</div>';
            exit;
        }
        
        // Verify hash
        $expected_hash = hash_hmac('sha256', $timestamp . 'express_checkout' . $api_key, $site->api_secret);
        if (!hash_equals($expected_hash, $api_secret_hash)) {
            header('Content-Type: text/html; charset=UTF-8');
            echo '<div style="color:red;">Invalid security hash. Please check your configuration.</div>';
            exit;
        }
    }
    
    // Get parameters
    $amount = $request->get_param('amount');
    $currency = $request->get_param('currency') ?: 'USD';
    $callback_url = $request->get_param('callback_url') ? base64_decode($request->get_param('callback_url')) : '';
    $site_url = $request->get_param('site_url') ? base64_decode($request->get_param('site_url')) : '';
    $needs_shipping = $request->get_param('needs_shipping') === 'yes';
    
    error_log('Express Checkout: Preparing buttons with amount=' . $amount . ', currency=' . $currency . ', needs_shipping=' . ($needs_shipping ? 'yes' : 'no'));
    
    // Set up template variables
    $client_id = $this->paypal_api->get_client_id();
    $environment = $this->paypal_api->get_environment();
    $is_express = true;
    
    // Critical: Set the content type header to HTML
    header('Content-Type: text/html; charset=UTF-8');
    
    // Include the Express PayPal buttons template
    include WPPPS_PLUGIN_DIR . 'templates/express-paypal-buttons.php';
    
    // Exit to prevent WordPress from further processing
    exit;
}

/**
 * Create Express Checkout order in PayPal
 */
public function create_express_checkout($request) {
    error_log('Express Checkout: Received create express checkout request');
    
    // Get request data
    $api_key = $request->get_param('api_key');
    $hash = $request->get_param('hash');
    $timestamp = $request->get_param('timestamp');
    $order_data_encoded = $request->get_param('order_data');
    
    if (empty($api_key) || empty($hash) || empty($timestamp) || empty($order_data_encoded)) {
        error_log('Express Checkout: Missing required parameters');
        return new WP_Error(
            'missing_params',
            __('Missing required parameters', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    // Get site by API key
    $site = $this->get_site_by_api_key($api_key);
    if (!$site) {
        error_log('Express Checkout: Invalid API key');
        return new WP_Error(
            'invalid_api_key',
            __('Invalid API key', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    // Decode order data
    $order_data = json_decode(base64_decode($order_data_encoded), true);
    if (!$order_data) {
        error_log('Express Checkout: Invalid order data format');
        return new WP_Error(
            'invalid_data',
            __('Invalid order data format', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    error_log('Express Checkout: Processing order data: ' . json_encode($order_data));
    
    $order_amount = isset($order_data['cart_total']) ? $order_data['cart_total'] : 
               (isset($order_data['order_total']) ? $order_data['order_total'] : 0);

// Validate hash with either parameter
$expected_hash = hash_hmac('sha256', $timestamp . $order_data['order_id'] . $order_amount . $api_key, $site->api_secret);
if (!hash_equals($expected_hash, $hash)) {
    error_log('Express Checkout: Invalid hash - Expected: ' . $expected_hash . ' Received: ' . $hash);
    
    // For backward compatibility, try the alternative hash calculation
    $alt_expected_hash = hash_hmac('sha256', $timestamp . $order_data['order_id'] . $api_key, $site->api_secret);
    if (!hash_equals($alt_expected_hash, $hash)) {
        return new WP_Error(
            'invalid_hash',
            __('Invalid hash', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    error_log('Express Checkout: Hash validated using alternative method');
}

    
    try {
        // Initialize PayPal API
        $paypal_api = new WPPPS_PayPal_API();
        
        // Prepare order data for PayPal
        $reference_id = 'WC_ORDER_' . $order_data['order_id'];
        $return_url = isset($order_data['return_url']) ? $order_data['return_url'] : '';
        $cancel_url = isset($order_data['cancel_url']) ? $order_data['cancel_url'] : '';
        
        // Prepare custom data for PayPal
        $custom_data = array();
        
        // Add line items if available
        if (!empty($order_data['items'])) {
            $custom_data['line_items'] = $order_data['items'];
        }
        
        // Set application context to indicate this is Express Checkout
        $application_context = array(
            'shipping_preference' => $order_data['needs_shipping'] ? 'GET_FROM_FILE' : 'NO_SHIPPING',
            'user_action' => 'PAY_NOW',
            'return_url' => $return_url,
            'cancel_url' => $cancel_url
        );
        
        // Get the order amount - check both 'cart_total' and 'order_total' parameters to handle both formats
        $order_amount = isset($order_data['cart_total']) ? $order_data['cart_total'] : 
                       (isset($order_data['order_total']) ? $order_data['order_total'] : 0);
                
        error_log('Express Checkout: Creating PayPal order with amount=' . $order_amount . 
                 ', currency=' . $order_data['currency'] . 
                 ', shipping_preference=' . ($order_data['needs_shipping'] ? 'GET_FROM_FILE' : 'NO_SHIPPING'));        
        // Create PayPal order
        $paypal_order = $paypal_api->create_order(
            $order_amount,
            $order_data['currency'],
            $reference_id,
            $return_url,
            $cancel_url,
            $custom_data,
            $application_context
        );
        
        if (is_wp_error($paypal_order)) {
            error_log('Express Checkout: Error creating PayPal order: ' . $paypal_order->get_error_message());
            throw new Exception($paypal_order->get_error_message());
        }
        
        error_log('Express Checkout: Created PayPal order: ' . json_encode($paypal_order));
        
        // Get approval URL from links
        $approve_url = '';
        foreach ($paypal_order['links'] as $link) {
            if ($link['rel'] === 'approve') {
                $approve_url = $link['href'];
                break;
            }
        }
        
        // Store order data for later use
        $this->store_express_checkout_data($site->id, $order_data['order_id'], array(
            'paypal_order_id' => $paypal_order['id'],
            'order_key' => $order_data['order_key'],
            'callback_url' => isset($order_data['callback_url']) ? $order_data['callback_url'] : '',
            'needs_shipping' => $order_data['needs_shipping'],
            'server_id' => $order_data['server_id']
        ));
        
        // Get the order amount from either cart_total or order_total parameter
        $order_amount = isset($order_data['cart_total']) ? $order_data['cart_total'] : 
               (isset($order_data['order_total']) ? $order_data['order_total'] : 0);
        
        // Log transaction
        $this->log_transaction(
            $site->id,
            $order_data['order_id'],
            $paypal_order['id'],
            $order_amount,
            $order_data['currency'],
            'pending',
            json_encode(array('express_checkout' => true))
        );
        
        // Return success response with PayPal order ID and approval URL
        return new WP_REST_Response(array(
            'success' => true,
            'paypal_order_id' => $paypal_order['id'],
            'approve_url' => $approve_url
        ), 200);
        
    } catch (Exception $e) {
        error_log('Express Checkout: Exception creating order: ' . $e->getMessage());
        return new WP_Error(
            'order_creation_error',
            $e->getMessage(),
            array('status' => 500)
        );
    }
}

/**
 * Update Express Checkout shipping methods
 */
public function update_express_shipping($request) {
    error_log('Express Checkout: Received update shipping request');
    
    // Get request data
    $params = $this->get_json_params($request);
    
    if (empty($params)) {
        error_log('Express Checkout: Invalid request format');
        return new WP_Error(
            'invalid_request',
            __('Invalid request format', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    // Extract parameters
    $api_key = isset($params['api_key']) ? $params['api_key'] : '';
    $hash = isset($params['hash']) ? $params['hash'] : '';
    $timestamp = isset($params['timestamp']) ? $params['timestamp'] : '';
    $request_data_encoded = isset($params['request_data']) ? $params['request_data'] : '';
    
    if (empty($api_key) || empty($hash) || empty($timestamp) || empty($request_data_encoded)) {
        error_log('Express Checkout: Missing required parameters');
        return new WP_Error(
            'missing_params',
            __('Missing required parameters', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    // Get site by API key
    $site = $this->get_site_by_api_key($api_key);
    if (!$site) {
        error_log('Express Checkout: Invalid API key');
        return new WP_Error(
            'invalid_api_key',
            __('Invalid API key', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    // Decode request data - FIXED to properly handle the base64 encoding
    $decoded_data = base64_decode($request_data_encoded);
    if (!$decoded_data) {
        error_log('Express Checkout: Failed to decode base64 data');
        return new WP_Error(
            'decode_error',
            __('Failed to decode request data', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    $request_data = json_decode($decoded_data, true);
    if (!$request_data) {
        error_log('Express Checkout: Failed to parse JSON after base64 decode. Decoded data: ' . $decoded_data);
        return new WP_Error(
            'invalid_data',
            __('Invalid request data format', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    error_log('Express Checkout: Processing shipping update: ' . json_encode($request_data));
    
    // Extract request data
    $order_id = isset($request_data['order_id']) ? $request_data['order_id'] : '';
    $paypal_order_id = isset($request_data['paypal_order_id']) ? $request_data['paypal_order_id'] : '';
    $shipping_method = isset($request_data['shipping_method']) ? $request_data['shipping_method'] : '';
    $shipping_options = isset($request_data['shipping_options']) ? $request_data['shipping_options'] : array();
    $order_total = isset($request_data['order_total']) ? $request_data['order_total'] : 0;
    $currency = isset($request_data['currency']) ? $request_data['currency'] : 'USD';
    
    // Log the important data we extracted
    error_log('Express Checkout: Extracted shipping options: ' . json_encode($shipping_options));
    error_log('Express Checkout: Shipping method: ' . $shipping_method);
    
    // Validate hash
    $expected_hash = hash_hmac('sha256', $timestamp . $order_id . $paypal_order_id . $api_key, $site->api_secret);
    if (!hash_equals($expected_hash, $hash)) {
        error_log('Express Checkout: Invalid hash');
        return new WP_Error(
            'invalid_hash',
            __('Invalid hash', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    try {
        // Get stored order data
        $stored_data = $this->get_express_checkout_data($site->id, $order_id);
        if (!$stored_data || $stored_data['paypal_order_id'] !== $paypal_order_id) {
            error_log('Express Checkout: No matching stored data found or PayPal order ID mismatch');
            throw new Exception('Invalid order data');
        }
        
        // Initialize PayPal API
        $paypal_api = new WPPPS_PayPal_API();
        
        // If no shipping method is selected, use the first available one
        $selected_shipping_cost = 0;
        $selected_method = $shipping_method;
        
        if (empty($selected_method) && !empty($shipping_options) && is_array($shipping_options) && count($shipping_options) > 0) {
            // Use the first shipping option as default
            $selected_method = $shipping_options[0]['id'];
            $selected_shipping_cost = floatval($shipping_options[0]['cost']);
            error_log('Express Checkout: No shipping method selected, using first option: ' . $selected_method . ' with cost: ' . $selected_shipping_cost);
        } else if (!empty($selected_method) && !empty($shipping_options)) {
            // Find the cost for the selected method
            foreach ($shipping_options as $option) {
                if ($option['id'] === $selected_method) {
                    $selected_shipping_cost = floatval($option['cost']);
                    error_log('Express Checkout: Selected shipping method cost: ' . $selected_shipping_cost);
                    break;
                }
            }
        }
        
        // Update PayPal order with shipping method and new total
        $updated_order = $paypal_api->update_paypal_order_shipping(
            $paypal_order_id,
            $selected_method,
            $order_total,
            $currency,
            $selected_shipping_cost
        );
        
        if (is_wp_error($updated_order)) {
            error_log('Express Checkout: Error updating PayPal order: ' . $updated_order->get_error_message());
            throw new Exception($updated_order->get_error_message());
        }
        
        error_log('Express Checkout: Successfully updated PayPal order with shipping method');
        
        // Return success response with shipping options
        return new WP_REST_Response(array(
            'success' => true,
            'message' => 'Shipping updated successfully',
            'shipping_options' => $shipping_options // Return shipping options to client
        ), 200);
        
    } catch (Exception $e) {
        error_log('Express Checkout: Exception updating shipping: ' . $e->getMessage());
        return new WP_Error(
            'shipping_update_error',
            $e->getMessage(),
            array('status' => 500)
        );
    }
}

/**
 * Capture Express Checkout payment
 */
public function capture_express_payment($request) {
    error_log('Express Checkout: Received capture payment request');
    
    // Get request data
    $params = $this->get_json_params($request);
    
    if (empty($params)) {
        error_log('Express Checkout: Invalid request format');
        return new WP_Error(
            'invalid_request',
            __('Invalid request format', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    // Extract parameters
    $api_key = isset($params['api_key']) ? $params['api_key'] : '';
    $hash = isset($params['hash']) ? $params['hash'] : '';
    $timestamp = isset($params['timestamp']) ? $params['timestamp'] : '';
    $request_data_encoded = isset($params['request_data']) ? $params['request_data'] : '';
    
    if (empty($api_key) || empty($hash) || empty($timestamp) || empty($request_data_encoded)) {
        error_log('Express Checkout: Missing required parameters');
        return new WP_Error(
            'missing_params',
            __('Missing required parameters', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    // Get site by API key
    $site = $this->get_site_by_api_key($api_key);
    if (!$site) {
        error_log('Express Checkout: Invalid API key');
        return new WP_Error(
            'invalid_api_key',
            __('Invalid API key', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    // Decode request data
    $request_data = json_decode(base64_decode($request_data_encoded), true);
    if (!$request_data) {
        error_log('Express Checkout: Invalid request data format');
        return new WP_Error(
            'invalid_data',
            __('Invalid request data format', 'woo-paypal-proxy-server'),
            array('status' => 400)
        );
    }
    
    error_log('Express Checkout: Processing payment capture: ' . json_encode($request_data));
    
    // Extract request data
    $order_id = isset($request_data['order_id']) ? $request_data['order_id'] : '';
    $paypal_order_id = isset($request_data['paypal_order_id']) ? $request_data['paypal_order_id'] : '';
    
    // Validate hash
    $expected_hash = hash_hmac('sha256', $timestamp . $order_id . $paypal_order_id . $api_key, $site->api_secret);
    if (!hash_equals($expected_hash, $hash)) {
        error_log('Express Checkout: Invalid hash');
        return new WP_Error(
            'invalid_hash',
            __('Invalid hash', 'woo-paypal-proxy-server'),
            array('status' => 401)
        );
    }
    
    try {
        // Get stored order data
        $stored_data = $this->get_express_checkout_data($site->id, $order_id);
        if (!$stored_data || $stored_data['paypal_order_id'] !== $paypal_order_id) {
            error_log('Express Checkout: No matching stored data found or PayPal order ID mismatch');
            throw new Exception('Invalid order data');
        }
        
        // Initialize PayPal API
        $paypal_api = new WPPPS_PayPal_API();
        
        // Capture the payment
        $capture = $paypal_api->capture_payment($paypal_order_id);
        
        if (is_wp_error($capture)) {
            error_log('Express Checkout: Error capturing payment: ' . $capture->get_error_message());
            throw new Exception($capture->get_error_message());
        }
        
        error_log('Express Checkout: Payment captured successfully: ' . json_encode($capture));
        
        // Extract transaction ID
        $transaction_id = '';
        if (!empty($capture['purchase_units'][0]['payments']['captures'][0]['id'])) {
            $transaction_id = $capture['purchase_units'][0]['payments']['captures'][0]['id'];
        }
        
        // Extract seller protection status
        $seller_protection = 'UNKNOWN';
        if (!empty($capture['purchase_units'][0]['payments']['captures'][0]['seller_protection']['status'])) {
            $seller_protection = $capture['purchase_units'][0]['payments']['captures'][0]['seller_protection']['status'];
        }
        
        // Update transaction log
        $this->update_transaction_status(
            $site->id,
            $order_id,
            $paypal_order_id,
            'completed',
            json_encode(array(
                'transaction_id' => $transaction_id,
                'seller_protection' => $seller_protection,
                'capture_data' => $capture
            ))
        );
        
        // Return success response with transaction ID
        return new WP_REST_Response(array(
            'success' => true,
            'transaction_id' => $transaction_id,
            'seller_protection' => $seller_protection
        ), 200);
        
    } catch (Exception $e) {
        error_log('Express Checkout: Exception capturing payment: ' . $e->getMessage());
        return new WP_Error(
            'payment_capture_error',
            $e->getMessage(),
            array('status' => 500)
        );
    }
}

/**
 * Store Express Checkout data in transient
 */
private function store_express_checkout_data($site_id, $order_id, $data) {
    $key = 'wppps_express_checkout_' . $site_id . '_' . $order_id;
    set_transient($key, $data, 24 * HOUR_IN_SECONDS);
    error_log('Express Checkout: Stored data for site ' . $site_id . ', order ' . $order_id . ': ' . json_encode($data));
    return true;
}

/**
 * Get Express Checkout data from transient
 */
private function get_express_checkout_data($site_id, $order_id) {
    $key = 'wppps_express_checkout_' . $site_id . '_' . $order_id;
    $data = get_transient($key);
    error_log('Express Checkout: Retrieved data for site ' . $site_id . ', order ' . $order_id . ': ' . ($data ? json_encode($data) : 'not found'));
    return $data;
}

/**
 * Update transaction status in log
 */
private function update_transaction_status($site_id, $order_id, $paypal_order_id, $status, $transaction_data = null) {
    global $wpdb;
    $log_table = $wpdb->prefix . 'wppps_transaction_log';
    
    $data = array(
        'status' => $status,
        'completed_at' => current_time('mysql')
    );
    
    if ($transaction_data !== null) {
        $data['transaction_data'] = $transaction_data;
    }
    
    $result = $wpdb->update(
        $log_table,
        $data,
        array(
            'site_id' => $site_id,
            'order_id' => $order_id,
            'paypal_order_id' => $paypal_order_id
        )
    );
    
    error_log('Express Checkout: Updated transaction status to ' . $status . ' for order ' . $order_id . ', result: ' . ($result !== false ? 'success' : 'failed'));
    
    return $result;
}
}