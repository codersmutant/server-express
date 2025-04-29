<?php
/**
 * PayPal API Integration for WooCommerce PayPal Proxy Server
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class to handle PayPal API integration
 */
class WPPPS_PayPal_API {
    
    /**
     * PayPal API Base URL
     */
    private $api_url;
    
    /**
     * PayPal Client ID
     */
    private $client_id;
    
    /**
     * PayPal Client Secret
     */
    private $client_secret;
    
    /**
     * PayPal Environment (sandbox or live)
     */
    private $environment;
    
    /**
     * Access Token
     */
    private $access_token;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->environment = get_option('wppps_paypal_environment', 'sandbox');
        $this->client_id = get_option('wppps_paypal_client_id', '');
        $this->client_secret = get_option('wppps_paypal_client_secret', '');
        
        // Set API URL based on environment
        $this->api_url = ($this->environment === 'sandbox') 
            ? 'https://api-m.sandbox.paypal.com' 
            : 'https://api-m.paypal.com';
    }
    
    /**
     * Get PayPal environment
     */
    public function get_environment() {
        return $this->environment;
    }
    
    /**
     * Get PayPal client ID
     */
    public function get_client_id() {
        return $this->client_id;
    }
    
    /**
     * Get PayPal SDK URL
     */
    public function get_sdk_url($currency = 'USD', $intent = 'capture') {
        $params = array(
            'client-id' => $this->client_id,
            'currency' => $currency,
            'intent' => $intent
        );
        
        return 'https://www.paypal.com/sdk/js?' . http_build_query($params);
    }
    
    /**
     * Get access token for API requests
     */
    private function get_access_token() {
        // Return existing token if we have one
        if (!empty($this->access_token)) {
            return $this->access_token;
        }
        
        // Set API endpoint
        $endpoint = $this->api_url . '/v1/oauth2/token';
        
        // Set up basic authentication
        $auth = base64_encode($this->client_id . ':' . $this->client_secret);
        
        // Set up request arguments
        $args = array(
            'method' => 'POST',
            'headers' => array(
                'Authorization' => 'Basic ' . $auth,
                'Content-Type' => 'application/x-www-form-urlencoded',
            ),
            'body' => 'grant_type=client_credentials',
            'timeout' => 30,
        );
        
        // Make the request
        $response = wp_remote_post($endpoint, $args);
        
        // Check for errors
        if (is_wp_error($response)) {
            $this->log_error('Failed to get access token: ' . $response->get_error_message());
            return false;
        }
        
        // Parse response
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        if (empty($body['access_token'])) {
            $this->log_error('Invalid access token response: ' . print_r($body, true));
            return false;
        }
        
        // Store the token
        $this->access_token = $body['access_token'];
        
        return $this->access_token;
    }
    
/**
 * Create PayPal order with detailed breakdown
 */
public function create_order($amount, $currency = 'USD', $reference_id = '', $return_url = '', $cancel_url = '', $custom_data = array()) {
    // Get access token
    $access_token = $this->get_access_token();
    
    if (!$access_token) {
        return new WP_Error('paypal_auth_error', __('Failed to authenticate with PayPal API', 'woo-paypal-proxy-server'));
    }
    
    // Set API endpoint
    $endpoint = $this->api_url . '/v2/checkout/orders';
    
    // Build request body with basic structure
    $payload = array(
        'intent' => 'CAPTURE',
        'purchase_units' => array(
            array(
                'amount' => array(
                    'currency_code' => $currency,
                    'value' => number_format($amount, 2, '.', ''),
                ),
            ),
        ),
        'application_context' => array(
            'shipping_preference' => !empty($custom_data['shipping_address']) ? 'SET_PROVIDED_ADDRESS' : 'GET_FROM_FILE',
            'billing_preference' => 'NO_BILLING',
            'user_action' => 'PAY_NOW',
            'brand_name' => get_bloginfo('name'),
            'landing_page' => 'BILLING',
        )
    );
    
    // Add reference ID if provided
    if (!empty($reference_id)) {
        $payload['purchase_units'][0]['reference_id'] = $reference_id;
    }
    
    // Add description if provided
    if (!empty($custom_data['description'])) {
        $payload['purchase_units'][0]['description'] = $custom_data['description'];
        $this->log_info('Adding description to PayPal API request: ' . $custom_data['description']);
    }
    
    // Process line items if available
    $has_line_items = !empty($custom_data['line_items']) && is_array($custom_data['line_items']);
    $this->log_info('Processing line items: ' . ($has_line_items ? 'Yes' : 'No'));
    
    if ($has_line_items) {
        $this->log_info('Number of line items: ' . count($custom_data['line_items']));
        
        // Initialize amounts for breakdown
        $item_total = 0;
        $tax_total = 0;
        $shipping_total = isset($custom_data['shipping_amount']) ? floatval($custom_data['shipping_amount']) : 0;
        $shipping_tax = isset($custom_data['shipping_tax']) ? floatval($custom_data['shipping_tax']) : 0;
        $tax_total += $shipping_tax;

        $this->log_info('Initial shipping amount: ' . $shipping_total);
        
        // Prepare items array for PayPal
        $items = array();
        
        foreach ($custom_data['line_items'] as $item) {
            // Validate item data
            if (empty($item['name']) || !isset($item['quantity']) || !isset($item['unit_price'])) {
                $this->log_info('Skipping invalid line item: ' . json_encode($item));
                continue;
            }
            
            $unit_price = floatval($item['unit_price']);
            $quantity = intval($item['quantity']);
            $line_total = $unit_price * $quantity;
            
            // Add to item total
            $item_total += $line_total;
            
            // Add tax if provided
            if (!empty($item['tax_amount'])) {
                $line_tax = floatval($item['tax_amount']);
                $tax_total += $line_tax;
                $this->log_info('Added line item tax: ' . $line_tax);
            }
            
            // Create the item for PayPal
            $paypal_item = array(
                'name' => substr($item['name'], 0, 127), // PayPal limits name to 127 chars
                'unit_amount' => array(
                    'currency_code' => $currency,
                    'value' => number_format($unit_price, 2, '.', '')
                ),
                'quantity' => $quantity
            );
            
            // Add description if available
            if (!empty($item['description'])) {
                $paypal_item['description'] = substr($item['description'], 0, 127);
            }
            
            // Add SKU if available
            if (!empty($item['sku'])) {
                $paypal_item['sku'] = substr($item['sku'], 0, 50);
            }
            
            $items[] = $paypal_item;
            $this->log_info('Added item: ' . $item['name'] . ' x ' . $quantity . ' @ ' . $unit_price);
        }
        
        // Log the breakdown totals
        $this->log_info('Calculated item_total: ' . $item_total);
        $this->log_info('Calculated tax_total: ' . $tax_total);
        $this->log_info('Calculated shipping_total: ' . $shipping_total);
        
        // Apply the breakdown only if we have valid totals
        if (!empty($items) && $item_total > 0) {
            // Create breakdown with correct values
            $breakdown = array(
                'item_total' => array(
                    'currency_code' => $currency,
                    'value' => number_format($item_total, 2, '.', '')
                )
            );
            
            // Only add tax if it's greater than zero
            if ($tax_total > 0) {
                $breakdown['tax_total'] = array(
                    'currency_code' => $currency,
                    'value' => number_format($tax_total, 2, '.', '')
                );
            }
            
            // Only add shipping if it's greater than zero
            if ($shipping_total > 0) {
                $breakdown['shipping'] = array(
                    'currency_code' => $currency,
                    'value' => number_format($shipping_total, 2, '.', '')
                );
            } else {
                // Still include shipping with zero value for clarity
                $breakdown['shipping'] = array(
                    'currency_code' => $currency,
                    'value' => '0.00'
                );
            }
            
            // Calculate expected total
            $expected_total = $item_total + $shipping_total + $tax_total;
            $actual_total = floatval($amount);
            
            $this->log_info('Expected total: ' . $expected_total);
            $this->log_info('Actual total: ' . $actual_total);
            
            // If the totals don't match, adjust one of the components to make it balance
            if (abs($expected_total - $actual_total) > 0.01) {
                $this->log_info('Totals don\'t match. Adjusting...');
                
                // Calculate the difference
                $difference = $actual_total - $expected_total;
                
                // If shipping is present, adjust it first
                if ($shipping_total > 0) {
                    $shipping_total += $difference;
                    $breakdown['shipping']['value'] = number_format($shipping_total, 2, '.', '');
                    $this->log_info('Adjusted shipping to: ' . $shipping_total);
                } 
                // Otherwise, adjust item_total
                else {
                    $item_total += $difference;
                    $breakdown['item_total']['value'] = number_format($item_total, 2, '.', '');
                    $this->log_info('Adjusted item_total to: ' . $item_total);
                }
            }
            
            // Set the breakdown and items in the payload
            $payload['purchase_units'][0]['amount']['breakdown'] = $breakdown;
            $payload['purchase_units'][0]['items'] = $items;
            
            $this->log_info('Added breakdown and ' . count($items) . ' line items to payload');
        } else {
            $this->log_info('No valid items or item_total is zero, skipping detailed breakdown');
        }
    }
    // Even if no line items, still add shipping breakdown if available
    else if (isset($custom_data['shipping_amount']) && floatval($custom_data['shipping_amount']) > 0) {
        $shipping_total = floatval($custom_data['shipping_amount']);
        $item_total = floatval($amount) - $shipping_total;
        
        if ($item_total >= 0) {
            $payload['purchase_units'][0]['amount']['breakdown'] = array(
                'item_total' => array(
                    'currency_code' => $currency,
                    'value' => number_format($item_total, 2, '.', '')
                ),
                'shipping' => array(
                    'currency_code' => $currency,
                    'value' => number_format($shipping_total, 2, '.', '')
                ),
                'tax_total' => array(
                    'currency_code' => $currency,
                    'value' => '0.00'
                )
            );
            
            $this->log_info('Added basic breakdown with shipping: ' . $shipping_total);
        }
    }
    
    // Add billing address if provided
    if (!empty($custom_data['billing_address'])) {
        $this->log_info('Adding billing address to PayPal request');
        
        $billing = $custom_data['billing_address'];
        
        // Add payer information with billing address
        $payload['payer'] = array(
            'name' => array(
                'given_name' => $billing['first_name'],
                'surname' => $billing['last_name']
            ),
            'email_address' => !empty($billing['email']) ? $billing['email'] : '',
            'phone' => !empty($billing['phone']) ? array(
                'phone_number' => array(
                    'national_number' => preg_replace('/[^0-9]/', '', $billing['phone'])
                )
            ) : null,
            'address' => array(
                'address_line_1' => $billing['address_1'],
                'address_line_2' => $billing['address_2'] ?: '',
                'admin_area_2' => $billing['city'],           // City
                'admin_area_1' => $billing['state'],          // State
                'postal_code' => $billing['postcode'],
                'country_code' => $billing['country']         // Country code
            )
        );
    }
    
    // Add shipping address if provided
    if (!empty($custom_data['shipping_address'])) {
        $this->log_info('Adding shipping address to PayPal request');
        
        // Format shipping address according to PayPal API specifications
        $shipping = $custom_data['shipping_address'];
        
        // Create properly formatted shipping data for PayPal
        $formatted_shipping = array(
            'name' => array(
                'full_name' => $shipping['first_name'] . ' ' . $shipping['last_name']
            ),
            'address' => array(
                'address_line_1' => $shipping['address_1'],
                'address_line_2' => $shipping['address_2'] ?: '',
                'admin_area_2' => $shipping['city'],           // City
                'admin_area_1' => $shipping['state'],          // State
                'postal_code' => $shipping['postcode'],
                'country_code' => $shipping['country']         // Country code
            )
        );
        
        // Add shipping to payload
        $payload['purchase_units'][0]['shipping'] = $formatted_shipping;
    }
    
    // Set up request arguments
    $args = array(
        'method' => 'POST',
        'headers' => array(
            'Authorization' => 'Bearer ' . $access_token,
            'Content-Type' => 'application/json',
        ),
        'body' => json_encode($payload),
        'timeout' => 30,
    );
    
    // Log the complete payload for debugging
    $this->log_info('PayPal order creation payload: ' . json_encode($payload));
    
    // Make the request
    $response = wp_remote_post($endpoint, $args);
    
    // Check for errors
    if (is_wp_error($response)) {
        $this->log_error('Failed to create PayPal order: ' . $response->get_error_message());
        return $response;
    }
    
    // Get response code
    $response_code = wp_remote_retrieve_response_code($response);
    
    if ($response_code !== 201) {
        $body = json_decode(wp_remote_retrieve_body($response), true);
        $error_message = $this->get_error_message($body);
        $this->log_error('PayPal API error (' . $response_code . '): ' . $error_message);
        return new WP_Error('paypal_api_error', $error_message);
    }
    
    // Parse response
    $body = json_decode(wp_remote_retrieve_body($response), true);
    
    if (empty($body['id'])) {
        $this->log_error('Invalid order creation response: ' . print_r($body, true));
        return new WP_Error('paypal_response_error', __('Invalid response from PayPal API', 'woo-paypal-proxy-server'));
    }
    
    return $body;
}
    
    /**
     * Capture payment for a PayPal order
     */
    public function capture_payment($order_id) {
        // Get access token
        $access_token = $this->get_access_token();
        
        if (!$access_token) {
            return new WP_Error('paypal_auth_error', __('Failed to authenticate with PayPal API', 'woo-paypal-proxy-server'));
        }
        
        // Set API endpoint
        $endpoint = $this->api_url . '/v2/checkout/orders/' . $order_id . '/capture';
        
        // Set up request arguments
        $args = array(
            'method' => 'POST',
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token,
                'Content-Type' => 'application/json',
                'Prefer' => 'return=representation',
            ),
            'body' => '{}',
            'timeout' => 30,
        );
        
        // Make the request
        $response = wp_remote_post($endpoint, $args);
        
        // Check for errors
        if (is_wp_error($response)) {
            $this->log_error('Failed to capture PayPal payment: ' . $response->get_error_message());
            return $response;
        }
        
        // Get response code
        $response_code = wp_remote_retrieve_response_code($response);
        
        if ($response_code !== 201) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            $error_message = $this->get_error_message($body);
            $this->log_error('PayPal API error (' . $response_code . '): ' . $error_message);
            return new WP_Error('paypal_api_error', $error_message);
        }
        
        // Parse response
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        return $body;
    }
    
    /**
     * Get PayPal order details
     */
    public function get_order_details($order_id) {
        // Get access token
        $access_token = $this->get_access_token();
        
        if (!$access_token) {
            return new WP_Error('paypal_auth_error', __('Failed to authenticate with PayPal API', 'woo-paypal-proxy-server'));
        }
        
        // Set API endpoint
        $endpoint = $this->api_url . '/v2/checkout/orders/' . $order_id;
        
        // Set up request arguments
        $args = array(
            'method' => 'GET',
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token,
                'Content-Type' => 'application/json',
            ),
            'timeout' => 30,
        );
        
        // Make the request
        $response = wp_remote_get($endpoint, $args);
        
        // Check for errors
        if (is_wp_error($response)) {
            $this->log_error('Failed to get PayPal order details: ' . $response->get_error_message());
            return $response;
        }
        
        // Get response code
        $response_code = wp_remote_retrieve_response_code($response);
        
        if ($response_code !== 200) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            $error_message = $this->get_error_message($body);
            $this->log_error('PayPal API error (' . $response_code . '): ' . $error_message);
            return new WP_Error('paypal_api_error', $error_message);
        }
        
        // Parse response
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        return $body;
    }
    
    /**
     * Process PayPal webhook event
     */
    public function process_webhook_event($event_data) {
        if (empty($event_data) || empty($event_data['event_type'])) {
            return new WP_Error('invalid_webhook', __('Invalid webhook data', 'woo-paypal-proxy-server'));
        }
        
        // Log webhook event
        $this->log_info('Received PayPal webhook: ' . $event_data['event_type']);
        
        // Process different event types
        switch ($event_data['event_type']) {
            case 'PAYMENT.CAPTURE.COMPLETED':
                return $this->process_payment_capture_completed($event_data);
                
            case 'PAYMENT.CAPTURE.DENIED':
                return $this->process_payment_capture_denied($event_data);
                
            default:
                // Just log the event for now
                $this->log_info('Unhandled webhook event: ' . $event_data['event_type']);
                return true;
        }
    }
    
    /**
     * Process PAYMENT.CAPTURE.COMPLETED webhook event
     */
    private function process_payment_capture_completed($event_data) {
        global $wpdb;
        
        // Extract the resource data
        $resource = isset($event_data['resource']) ? $event_data['resource'] : array();
        
        if (empty($resource['id']) || empty($resource['supplementary_data']['related_ids']['order_id'])) {
            return new WP_Error('invalid_resource', __('Invalid resource data in webhook', 'woo-paypal-proxy-server'));
        }
        
        $transaction_id = $resource['id'];
        $paypal_order_id = $resource['supplementary_data']['related_ids']['order_id'];
        
        // Find the transaction in our log
        $log_table = $wpdb->prefix . 'wppps_transaction_log';
        
        $transaction = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $log_table WHERE paypal_order_id = %s AND status = 'pending'",
            $paypal_order_id
        ));
        
        if (!$transaction) {
            $this->log_warning('Transaction not found for PayPal order ID: ' . $paypal_order_id);
            return new WP_Error('transaction_not_found', __('Transaction not found', 'woo-paypal-proxy-server'));
        }
        
        // Update the transaction status
        $wpdb->update(
            $log_table,
            array(
                'status' => 'completed',
                'completed_at' => current_time('mysql'),
                'transaction_data' => json_encode($event_data),
            ),
            array('id' => $transaction->id)
        );
        
        // Get the site information
        $sites_table = $wpdb->prefix . 'wppps_sites';
        $site = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $sites_table WHERE id = %d",
            $transaction->site_id
        ));
        
        if (!$site) {
            $this->log_error('Site not found for transaction: ' . $transaction->id);
            return new WP_Error('site_not_found', __('Site not found', 'woo-paypal-proxy-server'));
        }
        
        // Notify the original website about the completed payment
        $this->notify_site_of_payment_completion($site, $transaction, $paypal_order_id, $transaction_id);
        
        return true;
    }
    
    /**
     * Process PAYMENT.CAPTURE.DENIED webhook event
     */
    private function process_payment_capture_denied($event_data) {
        global $wpdb;
        
        // Extract the resource data
        $resource = isset($event_data['resource']) ? $event_data['resource'] : array();
        
        if (empty($resource['id']) || empty($resource['supplementary_data']['related_ids']['order_id'])) {
            return new WP_Error('invalid_resource', __('Invalid resource data in webhook', 'woo-paypal-proxy-server'));
        }
        
        $transaction_id = $resource['id'];
        $paypal_order_id = $resource['supplementary_data']['related_ids']['order_id'];
        
        // Find the transaction in our log
        $log_table = $wpdb->prefix . 'wppps_transaction_log';
        
        $transaction = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $log_table WHERE paypal_order_id = %s AND status = 'pending'",
            $paypal_order_id
        ));
        
        if (!$transaction) {
            $this->log_warning('Transaction not found for PayPal order ID: ' . $paypal_order_id);
            return new WP_Error('transaction_not_found', __('Transaction not found', 'woo-paypal-proxy-server'));
        }
        
        // Update the transaction status
        $wpdb->update(
            $log_table,
            array(
                'status' => 'failed',
                'completed_at' => current_time('mysql'),
                'transaction_data' => json_encode($event_data),
            ),
            array('id' => $transaction->id)
        );
        
        // Get the site information
        $sites_table = $wpdb->prefix . 'wppps_sites';
        $site = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $sites_table WHERE id = %d",
            $transaction->site_id
        ));
        
        if (!$site) {
            $this->log_error('Site not found for transaction: ' . $transaction->id);
            return new WP_Error('site_not_found', __('Site not found', 'woo-paypal-proxy-server'));
        }
        
        // Notify the original website about the failed payment
        $this->notify_site_of_payment_failure($site, $transaction, $paypal_order_id, $resource['status_details']['reason']);
        
        return true;
    }
    
    /**
     * Notify the original website about a completed payment
     */
    private function notify_site_of_payment_completion($site, $transaction, $paypal_order_id, $transaction_id) {
        // Generate security hash
        $timestamp = time();
        $hash_data = $timestamp . $transaction->order_id . 'completed' . $site->api_key;
        $hash = hash_hmac('sha256', $hash_data, $site->api_secret);
        
        // Build the callback URL
        $callback_url = trailingslashit($site->site_url) . 'wc-api/wpppc_callback';
        $params = array(
            'order_id' => $transaction->order_id,
            'status' => 'completed',
            'paypal_order_id' => $paypal_order_id,
            'transaction_id' => $transaction_id,
            'timestamp' => $timestamp,
            'hash' => $hash,
        );
        
        $url = add_query_arg($params, $callback_url);
        
        // Make the request
        $response = wp_remote_get($url, array(
            'timeout' => 30,
            'sslverify' => false,
        ));
        
        // Log the result
        if (is_wp_error($response)) {
            $this->log_error('Failed to notify site of payment completion: ' . $response->get_error_message());
        } else {
            $this->log_info('Site notified of payment completion. Response code: ' . wp_remote_retrieve_response_code($response));
        }
        
        return $response;
    }
    
    /**
     * Notify the original website about a failed payment
     */
    private function notify_site_of_payment_failure($site, $transaction, $paypal_order_id, $reason) {
        // Generate security hash
        $timestamp = time();
        $hash_data = $timestamp . $transaction->order_id . 'failed' . $site->api_key;
        $hash = hash_hmac('sha256', $hash_data, $site->api_secret);
        
        // Build the callback URL
        $callback_url = trailingslashit($site->site_url) . 'wc-api/wpppc_callback';
        $params = array(
            'order_id' => $transaction->order_id,
            'status' => 'failed',
            'paypal_order_id' => $paypal_order_id,
            'reason' => urlencode($reason),
            'timestamp' => $timestamp,
            'hash' => $hash,
        );
        
        $url = add_query_arg($params, $callback_url);
        
        // Make the request
        $response = wp_remote_get($url, array(
            'timeout' => 30,
            'sslverify' => false,
        ));
        
        // Log the result
        if (is_wp_error($response)) {
            $this->log_error('Failed to notify site of payment failure: ' . $response->get_error_message());
        } else {
            $this->log_info('Site notified of payment failure. Response code: ' . wp_remote_retrieve_response_code($response));
        }
        
        return $response;
    }
    
    /**
     * Extract error message from PayPal API response
     */
    private function get_error_message($response) {
        if (isset($response['message'])) {
            return $response['message'];
        }
        
        if (isset($response['error_description'])) {
            return $response['error_description'];
        }
        
        if (isset($response['details']) && is_array($response['details']) && !empty($response['details'][0]['description'])) {
            return $response['details'][0]['description'];
        }
        
        return __('Unknown PayPal error', 'woo-paypal-proxy-server');
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
    
    /**
     * Log an info message
     */
    private function log_info($message) {
        if (function_exists('wc_get_logger')) {
            $logger = wc_get_logger();
            $logger->info($message, array('source' => 'woo-paypal-proxy-server'));
        } else {
            error_log('[WooCommerce PayPal Proxy Server] Info: ' . $message);
        }
    }
    
/**
 * Create a PayPal order specifically for Express Checkout
 * With enhanced shipping and address handling
 */
public function create_express_order($amount, $currency = 'USD', $reference_id = '', $return_url = '', $cancel_url = '', $custom_data = array()) {
    // Get access token
    $access_token = $this->get_access_token();
    
    if (!$access_token) {
        return new WP_Error('paypal_auth_error', __('Failed to authenticate with PayPal API', 'woo-paypal-proxy-server'));
    }
    
    // Set API endpoint
    $endpoint = $this->api_url . '/v2/checkout/orders';
    
    // Log initial data
    $this->log_info('Creating Express Checkout PayPal order with amount: ' . $amount . ' ' . $currency);
    
    // Calculate subtotal, shipping and tax amounts (if available)
    $subtotal = isset($custom_data['subtotal']) ? $custom_data['subtotal'] : $amount;
    $shipping_amount = isset($custom_data['shipping_amount']) ? $custom_data['shipping_amount'] : 0;
    $tax_amount = isset($custom_data['tax_total']) ? $custom_data['tax_total'] : 0;
    
    // Build initial amount structure with breakdown
    $amount_breakdown = array(
        'item_total' => array(
            'currency_code' => $currency,
            'value' => number_format($subtotal, 2, '.', '')
        )
    );
    
    // Add shipping if available
    if ($shipping_amount > 0) {
        $amount_breakdown['shipping'] = array(
            'currency_code' => $currency,
            'value' => number_format($shipping_amount, 2, '.', '')
        );
    }
    
    // Add tax if available
    if ($tax_amount > 0) {
        $amount_breakdown['tax_total'] = array(
            'currency_code' => $currency,
            'value' => number_format($tax_amount, 2, '.', '')
        );
    }
    
    // Add other required fields
    $amount_breakdown['handling'] = array(
        'currency_code' => $currency,
        'value' => '0.00'
    );
    
    $amount_breakdown['discount'] = array(
        'currency_code' => $currency,
        'value' => '0.00'
    );
    
    // Build request body with basic structure
    $payload = array(
        'intent' => 'CAPTURE',
        'purchase_units' => array(
            array(
                'reference_id' => 'default',
                'amount' => array(
                    'currency_code' => $currency,
                    'value' => number_format($amount, 2, '.', ''),
                    'breakdown' => $amount_breakdown
                ),
            ),
        ),
        'application_context' => array(
            'shipping_preference' => 'GET_FROM_FILE', // Always use GET_FROM_FILE for Express Checkout
            'user_action' => 'PAY_NOW',
            'brand_name' => get_bloginfo('name'),
            'landing_page' => 'BILLING',
            'return_url' => !empty($return_url) ? $return_url : site_url(),
            'cancel_url' => !empty($cancel_url) ? $cancel_url : site_url(),
        )
    );
    
    // Override application context with custom data if provided
    if (!empty($custom_data['application_context'])) {
        $payload['application_context'] = array_merge(
            $payload['application_context'],
            $custom_data['application_context']
        );
    }
    
    // Add reference ID if provided
    if (!empty($reference_id)) {
        $payload['purchase_units'][0]['reference_id'] = $reference_id;
    }
    
    // Add description if provided
    if (!empty($custom_data['description'])) {
        $payload['purchase_units'][0]['description'] = $custom_data['description'];
    }
    
    // Process line items if available
    if (!empty($custom_data['line_items']) && is_array($custom_data['line_items'])) {
        $this->log_info('Processing ' . count($custom_data['line_items']) . ' line items for Express Checkout');
        
        $items = array();
        foreach ($custom_data['line_items'] as $item) {
            // Skip invalid items
            if (empty($item['name']) || !isset($item['quantity']) || !isset($item['price'])) {
                $this->log_info('Skipping invalid line item: ' . json_encode($item));
                continue;
            }
            
            // Create properly formatted item
            $paypal_item = array(
                'name' => substr($item['name'], 0, 127), // PayPal limits name to 127 chars
                'unit_amount' => array(
                    'currency_code' => $currency,
                    'value' => number_format(floatval($item['price']), 2, '.', '')
                ),
                'quantity' => intval($item['quantity']),
                'sku' => !empty($item['sku']) ? substr($item['sku'], 0, 50) : ''
            );
            
            // Add description if available, or generate one with product ID
            if (!empty($item['description'])) {
                $paypal_item['description'] = substr($item['description'], 0, 127);
            } elseif (!empty($item['product_id'])) {
                $paypal_item['description'] = 'Product ID: ' . $item['product_id'];
            }
            
            $items[] = $paypal_item;
        }
        
        // Add items to payload
        if (!empty($items)) {
            $payload['purchase_units'][0]['items'] = $items;
        }
    }
    
    // Add shipping address to purchase unit if provided
    if (!empty($custom_data['shipping_address'])) {
        $shipping = $custom_data['shipping_address'];
        
        // Format shipping address according to PayPal requirements
        $shipping_address = array(
            'name' => array(
                'full_name' => (!empty($shipping['first_name']) ? $shipping['first_name'] : '') . ' ' . 
                              (!empty($shipping['last_name']) ? $shipping['last_name'] : '')
            ),
            'address' => array(
                'address_line_1' => isset($shipping['address_1']) ? $shipping['address_1'] : '',
                'address_line_2' => isset($shipping['address_2']) ? $shipping['address_2'] : '',
                'admin_area_2' => isset($shipping['city']) ? $shipping['city'] : '',           // City
                'admin_area_1' => isset($shipping['state']) ? $shipping['state'] : '',         // State
                'postal_code' => isset($shipping['postcode']) ? $shipping['postcode'] : '',
                'country_code' => isset($shipping['country']) ? $shipping['country'] : ''      // Country code
            )
        );
        
        // Add shipping to purchase unit
        $payload['purchase_units'][0]['shipping'] = $shipping_address;
    }
    
    // Add shipping options if provided
    if (!empty($custom_data['shipping_options']) && is_array($custom_data['shipping_options'])) {
        $shipping_options = array();
        $selected_option_id = !empty($custom_data['selected_shipping_option']) ? 
                             $custom_data['selected_shipping_option'] : '';
        
        foreach ($custom_data['shipping_options'] as $option) {
            $shipping_option = array(
                'id' => $option['id'],
                'label' => $option['label'],
                'type' => 'SHIPPING',
                'selected' => ($option['id'] === $selected_option_id),
                'amount' => array(
                    'value' => number_format(floatval($option['cost']), 2, '.', ''),
                    'currency_code' => $currency
                )
            );
            
            $shipping_options[] = $shipping_option;
        }
        
        if (!empty($shipping_options)) {
            if (!isset($payload['purchase_units'][0]['shipping'])) {
                $payload['purchase_units'][0]['shipping'] = array();
            }
            
            $payload['purchase_units'][0]['shipping']['options'] = $shipping_options;
        }
    }
    
    // Add billing address to payer if provided
    if (!empty($custom_data['billing_address'])) {
        $billing = $custom_data['billing_address'];
        
        // Create payer with billing address
        $payer = array();
        
        // Add name if available
        if (!empty($billing['first_name']) || !empty($billing['last_name'])) {
            $payer['name'] = array(
                'given_name' => !empty($billing['first_name']) ? $billing['first_name'] : '',
                'surname' => !empty($billing['last_name']) ? $billing['last_name'] : ''
            );
        }
        
        // Add email if available
        if (!empty($billing['email'])) {
            $payer['email_address'] = $billing['email'];
        }
        
        // Add phone if available
        if (!empty($billing['phone'])) {
            $payer['phone'] = array(
                'phone_number' => array(
                    'national_number' => preg_replace('/[^0-9]/', '', $billing['phone'])
                )
            );
        }
        
        // Add address if available
        if (!empty($billing['address_1'])) {
            $payer['address'] = array(
                'address_line_1' => $billing['address_1'],
                'address_line_2' => !empty($billing['address_2']) ? $billing['address_2'] : '',
                'admin_area_2' => !empty($billing['city']) ? $billing['city'] : '',           // City
                'admin_area_1' => !empty($billing['state']) ? $billing['state'] : '',         // State
                'postal_code' => !empty($billing['postcode']) ? $billing['postcode'] : '',
                'country_code' => !empty($billing['country']) ? $billing['country'] : ''     // Country code
            );
        }
        
        // Add payer to payload if we have data
        if (!empty($payer)) {
            $payload['payer'] = $payer;
        }
    }
    
    // Log the final payload
    $this->log_info('Express Checkout final payload: ' . json_encode($payload));
    
    // Set up request arguments
    $args = array(
        'method' => 'POST',
        'headers' => array(
            'Authorization' => 'Bearer ' . $access_token,
            'Content-Type' => 'application/json',
            'PayPal-Request-Id' => 'EXPRESS-' . uniqid(), // Unique ID for idempotency
        ),
        'body' => json_encode($payload),
        'timeout' => 30,
    );
    
    // Make the request
    $response = wp_remote_post($endpoint, $args);
    
    // Check for errors
    if (is_wp_error($response)) {
        $this->log_error('Failed to create Express Checkout PayPal order: ' . $response->get_error_message());
        return $response;
    }
    
    // Get response code
    $response_code = wp_remote_retrieve_response_code($response);
    
    if ($response_code !== 201) {
        $body = json_decode(wp_remote_retrieve_body($response), true);
        $error_message = $this->get_error_message($body);
        $this->log_error('PayPal API error (' . $response_code . '): ' . $error_message);
        return new WP_Error('paypal_api_error', $error_message);
    }
    
    // Parse response
    $body = json_decode(wp_remote_retrieve_body($response), true);
    
    if (empty($body['id'])) {
        $this->log_error('Invalid order creation response: ' . print_r($body, true));
        return new WP_Error('paypal_response_error', __('Invalid response from PayPal API', 'woo-paypal-proxy-server'));
    }
    
    $this->log_info('Express Checkout PayPal order created successfully: ' . $body['id']);
    
    return $body;
}
}