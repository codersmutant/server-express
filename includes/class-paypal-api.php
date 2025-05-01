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

*/
    
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
 * Create PayPal order with Express Checkout options
 */
public function create_order($amount, $currency = 'USD', $reference_id = '', $return_url = '', $cancel_url = '', $custom_data = array(), $application_context = array()) {
    // Get access token
    $access_token = $this->get_access_token();
    
    if (!$access_token) {
        return new WP_Error('paypal_auth_error', __('Failed to authenticate with PayPal API', 'woo-paypal-proxy-server'));
    }
    
    // Set API endpoint
    $endpoint = $this->api_url . '/v2/checkout/orders';
    
    // Express checkout flag
    $is_express = !empty($custom_data['express_checkout']) || !empty($application_context);
    
    // Process line items if available
    $has_line_items = !empty($custom_data['line_items']) && is_array($custom_data['line_items']);
    $this->log_info('Processing line items: ' . ($has_line_items ? 'Yes' : 'No'));
    
    // Initialize breakdown values
    $item_total = 0;
    $tax_total = 0;
    $shipping_total = isset($custom_data['shipping_amount']) ? floatval($custom_data['shipping_amount']) : 0;
    $shipping_tax = isset($custom_data['shipping_tax']) ? floatval($custom_data['shipping_tax']) : 0;
    $discount_total = isset($custom_data['discount_total']) ? floatval($custom_data['discount_total']) : 0;
    $handling_total = 0;
    $tax_total += $shipping_tax;
    
    // Prepare items array for PayPal
    $items = array();
    
    if ($has_line_items) {
        $this->log_info('Number of line items: ' . count($custom_data['line_items']));
        
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
                'quantity' => $quantity,
                'unit_amount' => array(
                    'currency_code' => $currency,
                    'value' => number_format($unit_price, 2, '.', '')
                )
            );
            
            // Add description if available
            if (!empty($item['description'])) {
                $paypal_item['description'] = substr($item['description'], 0, 127);
            } else if (!empty($item['product_id'])) {
                $paypal_item['description'] = 'Product ID: ' . $item['product_id'];
            }
            
            // Add SKU if available
            if (!empty($item['sku'])) {
                $paypal_item['sku'] = substr($item['sku'], 0, 50);
            } else if (!empty($item['product_id'])) {
                $paypal_item['sku'] = $item['product_id'];
            }
            
            $items[] = $paypal_item;
            $this->log_info('Added item: ' . $item['name'] . ' x ' . $quantity . ' @ ' . $unit_price);
        }
    }
    
    // Create complete breakdown
    $breakdown = array();
    
    // Always include item_total
    $breakdown['item_total'] = array(
        'currency_code' => $currency,
        'value' => number_format($item_total > 0 ? $item_total : $amount, 2, '.', '')
    );
    
    // Include tax_total if applicable
    if ($tax_total > 0) {
        $breakdown['tax_total'] = array(
            'currency_code' => $currency,
            'value' => number_format($tax_total, 2, '.', '')
        );
    }
    
    // Always include shipping
    $breakdown['shipping'] = array(
        'currency_code' => $currency,
        'value' => number_format($shipping_total, 2, '.', '')
    );
    
    // Include discount if applicable
    if ($discount_total > 0) {
        $breakdown['discount'] = array(
            'currency_code' => $currency,
            'value' => number_format($discount_total, 2, '.', '')
        );
    } else {
        // Add zero discount for full structure
        $breakdown['discount'] = array(
            'currency_code' => $currency,
            'value' => '0.00'
        );
    }
    
    // Include handling
    $breakdown['handling'] = array(
        'currency_code' => $currency,
        'value' => number_format($handling_total, 2, '.', '')
    );
    
    // Calculate expected total (should match amount parameter)
    $expected_total = $item_total + $shipping_total + $tax_total - $discount_total + $handling_total;
    $actual_total = floatval($amount);
    
    // Adjust if totals don't match
    if (abs($expected_total - $actual_total) > 0.01) {
        $this->log_info("Totals don't match. Expected: $expected_total, Actual: $actual_total");
        // Difference between actual and expected
        $difference = $actual_total - $expected_total;
        
        // If we have line items, adjust one of the components to balance
        if ($has_line_items) {
            if ($shipping_total > 0) {
                // Adjust shipping first if possible
                $shipping_total += $difference;
                $breakdown['shipping']['value'] = number_format($shipping_total, 2, '.', '');
                $this->log_info('Adjusted shipping to: ' . $shipping_total);
            } elseif ($tax_total > 0) {
                // Otherwise adjust tax
                $tax_total += $difference;
                $breakdown['tax_total']['value'] = number_format($tax_total, 2, '.', '');
                $this->log_info('Adjusted tax_total to: ' . $tax_total);
            } else {
                // Last resort: adjust item_total
                $item_total += $difference;
                $breakdown['item_total']['value'] = number_format($item_total, 2, '.', '');
                $this->log_info('Adjusted item_total to: ' . $item_total);
            }
        }
    }
    
    // Build purchase units array
    $purchase_unit = array(
        'amount' => array(
            'currency_code' => $currency,
            'value' => number_format($amount, 2, '.', ''),
            'breakdown' => $breakdown
        )
    );
    
    // Add reference ID if provided or use 'default'
    $purchase_unit['reference_id'] = !empty($reference_id) ? $reference_id : 'default';
    
    // Add line items if available
    if (!empty($items)) {
        $purchase_unit['items'] = $items;
    }
    
    // Build complete request body
    $payload = array(
        'intent' => 'CAPTURE',
        'purchase_units' => array($purchase_unit)
    );
    
    // Add payer information if available
    if (!empty($custom_data['billing_address'])) {
        $billing = $custom_data['billing_address'];
        
        $payload['payer'] = array(
            'name' => array(
                'given_name' => $billing['first_name'],
                'surname' => $billing['last_name']
            )
        );
        
        if (!empty($billing['email'])) {
            $payload['payer']['email_address'] = $billing['email'];
        }
        
        if (!empty($billing['phone'])) {
            $payload['payer']['phone'] = array(
                'phone_number' => array(
                    'national_number' => preg_replace('/[^0-9]/', '', $billing['phone'])
                )
            );
        }
        
        if (!empty($billing['address_1'])) {
            $payload['payer']['address'] = array(
                'address_line_1' => $billing['address_1'],
                'address_line_2' => $billing['address_2'] ?: '',
                'admin_area_2' => $billing['city'],
                'admin_area_1' => $billing['state'],
                'postal_code' => $billing['postcode'],
                'country_code' => $billing['country']
            );
        }
    }
    
    // Add shipping address if provided
    if (!empty($custom_data['shipping_address'])) {
        $shipping = $custom_data['shipping_address'];
        
        $purchase_unit['shipping'] = array(
            'name' => array(
                'full_name' => $shipping['first_name'] . ' ' . $shipping['last_name']
            ),
            'address' => array(
                'address_line_1' => $shipping['address_1'],
                'address_line_2' => $shipping['address_2'] ?: '',
                'admin_area_2' => $shipping['city'],
                'admin_area_1' => $shipping['state'],
                'postal_code' => $shipping['postcode'],
                'country_code' => $shipping['country']
            )
        );
        
        // Update purchase_units with shipping info
        $payload['purchase_units'][0] = $purchase_unit;
    }
    
    // Add application context - this controls the flow in PayPal's interface
    if (!empty($application_context)) {
        $payload['application_context'] = $application_context;
    } else {
        $payload['application_context'] = array(
            'shipping_preference' => !empty($custom_data['shipping_address']) ? 'SET_PROVIDED_ADDRESS' : 'GET_FROM_FILE',
            'user_action' => 'PAY_NOW',
            'brand_name' => get_bloginfo('name')
        );
        
        // Add return and cancel URLs if provided
        if (!empty($return_url)) {
            $payload['application_context']['return_url'] = $return_url;
        }
        
        if (!empty($cancel_url)) {
            $payload['application_context']['cancel_url'] = $cancel_url;
        }
    }
    
    // Set up request arguments
    $args = array(
        'method' => 'POST',
        'headers' => array(
            'Authorization' => 'Bearer ' . $access_token,
            'Content-Type' => 'application/json',
            'Prefer' => 'return=representation'
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
 * Update PayPal order with shipping information with proper tax handling
 */
public function update_paypal_order_shipping($paypal_order_id, $shipping_option_id, $amount, $currency = 'USD', $shipping_cost = 0, $shipping_options = array()) {
    // Get access token
    $access_token = $this->get_access_token();
    
    if (!$access_token) {
        return new WP_Error('paypal_auth_error', __('Failed to authenticate with PayPal API', 'woo-paypal-proxy-server'));
    }
    
    // Set API endpoint
    $endpoint = $this->api_url . '/v2/checkout/orders/' . $paypal_order_id;
    
    // First, get the current order details to preserve information
    $current_order = $this->get_order_details($paypal_order_id);
    
    if (is_wp_error($current_order)) {
        $this->log_error('Failed to get current order details: ' . $current_order->get_error_message());
        return $current_order;
    }
    
    $this->log_info('Retrieved current order details for update: ' . json_encode($current_order));
    
    // Extract reference ID from the response or use default
    $reference_id = isset($current_order['purchase_units'][0]['reference_id']) ? 
        $current_order['purchase_units'][0]['reference_id'] : 'default';
    
    // Extract any existing items from the order
    $items = isset($current_order['purchase_units'][0]['items']) ? 
        $current_order['purchase_units'][0]['items'] : array();
    
    // Calculate the base amount (items only)
    $item_total = isset($current_order['purchase_units'][0]['amount']['breakdown']['item_total']['value']) ? 
        floatval($current_order['purchase_units'][0]['amount']['breakdown']['item_total']['value']) : $amount - $shipping_cost;
    
    // Calculate tax amount - initially include only product tax
    $tax_total = isset($current_order['purchase_units'][0]['amount']['breakdown']['tax_total']['value']) ? 
        floatval($current_order['purchase_units'][0]['amount']['breakdown']['tax_total']['value']) : 0;
    
    // Get discount if available
    $discount = isset($current_order['purchase_units'][0]['amount']['breakdown']['discount']['value']) ? 
        floatval($current_order['purchase_units'][0]['amount']['breakdown']['discount']['value']) : 0;
    
    // Get handling if available
    $handling = isset($current_order['purchase_units'][0]['amount']['breakdown']['handling']['value']) ? 
        floatval($current_order['purchase_units'][0]['amount']['breakdown']['handling']['value']) : 0;
    
    // Format shipping options for PayPal if provided
    $paypal_shipping_options = array();
    $selected_shipping_cost = 0;
    $shipping_tax = 0; // Initialize shipping tax
    
    if (!empty($shipping_options)) {
        // Find if we have the selected shipping option in our array
        $selected_option = null;
        
        foreach ($shipping_options as $option) {
            // Convert option cost to float to ensure accurate comparison
            $option_cost = floatval($option['cost']);
            
            // Create the PayPal format option
            $paypal_option = array(
                'id' => $option['id'],
                'label' => $option['label'],
                'type' => 'SHIPPING',
                'selected' => ($option['id'] === $shipping_option_id),
                'amount' => array(
                    'value' => number_format($option_cost, 2, '.', ''),
                    'currency_code' => $currency
                )
            );
            
            $paypal_shipping_options[] = $paypal_option;
            
            // If this is the selected option, store its cost and tax
            if ($option['id'] === $shipping_option_id) {
                $selected_option = $option;
                $selected_shipping_cost = $option_cost;
                
                // CRITICAL: Extract shipping tax if available
                if (isset($option['tax'])) {
                    $shipping_tax = floatval($option['tax']);
                    $this->log_info("Found shipping tax: {$shipping_tax} for option {$option['label']}");
                }
                
                $this->log_info("Found selected shipping option: {$option['label']} with cost {$option_cost}");
            }
        }
        
        // If we didn't find the selected option in our array but have a shipping_option_id
        if (!$selected_option && !empty($shipping_option_id) && !empty($shipping_cost)) {
            $selected_shipping_cost = floatval($shipping_cost);
            $this->log_info("Using provided shipping cost: {$selected_shipping_cost}");
        }
        // If we still don't have a selected option but have options, select the first one
        else if (!$selected_option && !empty($paypal_shipping_options)) {
            $paypal_shipping_options[0]['selected'] = true;
            $selected_shipping_cost = floatval($shipping_options[0]['cost']);
            
            // Extract shipping tax from the first option if available
            if (isset($shipping_options[0]['tax'])) {
                $shipping_tax = floatval($shipping_options[0]['tax']);
                $this->log_info("Using shipping tax from first option: {$shipping_tax}");
            }
            
            $this->log_info("No selected option provided, using first option with cost: {$selected_shipping_cost}");
        }
    }
    
    // CRITICAL: Add shipping tax to the total tax amount
    if ($shipping_tax > 0) {
        $this->log_info("Adding shipping tax {$shipping_tax} to product tax {$tax_total}");
        $tax_total += $shipping_tax;
        $this->log_info("New total tax amount: {$tax_total}");
    }
    
    // CRITICAL: Use the actual selected shipping cost, not the passed-in shipping_cost parameter
    $shipping_total = $selected_shipping_cost;
    $this->log_info("Using shipping cost for breakdown: {$shipping_total}");
    
    // Recalculate the total with the correct shipping cost and tax
    $recalculated_total = $item_total + $shipping_total + $tax_total - $discount + $handling;
    $this->log_info("Recalculated total: {$recalculated_total} (item_total:{$item_total} + shipping:{$shipping_total} + tax:{$tax_total} - discount:{$discount} + handling:{$handling})");
    
    // If the recalculated total doesn't match the input amount, log a warning
    if (abs($recalculated_total - floatval($amount)) > 0.01) {
        $this->log_info("Warning: Recalculated total ($recalculated_total) doesn't match input amount ($amount). Using recalculated total.");
        // Use the recalculated amount instead of the input amount
        $amount = $recalculated_total;
    }
    
    // Check if prices include tax
    $prices_include_tax = isset($current_order['purchase_units'][0]['amount']['breakdown']['item_total']['includes_tax']) && 
                         $current_order['purchase_units'][0]['amount']['breakdown']['item_total']['includes_tax'] === true;

    // For WooCommerce tax display, we can also check directly
    if (!isset($prices_include_tax)) {
        $prices_include_tax = wc_prices_include_tax();
    }

    $this->log_info("PayPal order prices include tax: " . ($prices_include_tax ? 'Yes' : 'No'));

    // Create the breakdown with proper tax handling
    $breakdown = array();
    
    // Add item_total with tax-inclusive flag if needed
    if ($prices_include_tax) {
        $breakdown['item_total'] = array(
            'currency_code' => $currency,
            'value' => number_format($item_total, 2, '.', ''),
            'includes_tax' => true
        );
    } else {
        $breakdown['item_total'] = array(
            'currency_code' => $currency,
            'value' => number_format($item_total, 2, '.', '')
        );
    }
    
    // Add shipping
    $breakdown['shipping'] = array(
        'currency_code' => $currency,
        'value' => number_format($shipping_total, 2, '.', '')
    );
    
    // Add tax_total
    $breakdown['tax_total'] = array(
        'currency_code' => $currency,
        'value' => number_format($tax_total, 2, '.', '')
    );
    
    // Add discount if we have it
    if ($discount > 0) {
        $breakdown['discount'] = array(
            'currency_code' => $currency,
            'value' => number_format($discount, 2, '.', '')
        );
    } else {
        $breakdown['discount'] = array(
            'currency_code' => $currency,
            'value' => '0.00'
        );
    }
    
    // Add handling
    $breakdown['handling'] = array(
        'currency_code' => $currency,
        'value' => number_format($handling, 2, '.', '')
    );
    
    // Prepare the full purchase unit for the PATCH request
    $purchase_unit = array(
        'amount' => array(
            'value' => number_format(floatval($amount), 2, '.', ''),
            'currency_code' => $currency,
            'breakdown' => $breakdown
        ),
        'reference_id' => $reference_id
    );
    
    // Include the items if we have them
    if (!empty($items)) {
        $purchase_unit['items'] = $items;
    }
    
    // Include shipping options if available
    if (!empty($paypal_shipping_options)) {
        $purchase_unit['shipping'] = array(
            'options' => $paypal_shipping_options
        );
        
        // Add shipping address from original order if available
        if (isset($current_order['purchase_units'][0]['shipping']['address'])) {
            $purchase_unit['shipping']['address'] = $current_order['purchase_units'][0]['shipping']['address'];
        }
        
        // Add shipping name from original order if available
        if (isset($current_order['purchase_units'][0]['shipping']['name'])) {
            $purchase_unit['shipping']['name'] = $current_order['purchase_units'][0]['shipping']['name'];
        }
    }
    
    // Get payee information from original order if available
    if (isset($current_order['purchase_units'][0]['payee'])) {
        $purchase_unit['payee'] = $current_order['purchase_units'][0]['payee'];
    }
    
    // Create the PATCH operation
    $patches = array(
        array(
            'op' => 'replace',
            'path' => "/purchase_units/@reference_id=='{$reference_id}'",
            'value' => $purchase_unit
        )
    );
    
    // Set up request arguments
    $args = array(
        'method' => 'PATCH',
        'headers' => array(
            'Authorization' => 'Bearer ' . $access_token,
            'Content-Type' => 'application/json',
        ),
        'body' => json_encode($patches),
        'timeout' => 30,
    );
    
    // Log the patch request
    $this->log_info('PayPal order update (PATCH) payload: ' . json_encode($patches));
    
    // Make the request
    $response = wp_remote_request($endpoint, $args);
    
    // Check for errors
    if (is_wp_error($response)) {
        $this->log_error('Failed to update PayPal order: ' . $response->get_error_message());
        return $response;
    }
    
    // Get response code - 204 is success with no content for PATCH
    $response_code = wp_remote_retrieve_response_code($response);
    
    if ($response_code !== 204) {
        $body = json_decode(wp_remote_retrieve_body($response), true);
        $error_message = $this->get_error_message($body);
        $this->log_error('PayPal API error (' . $response_code . '): ' . $error_message);
        return new WP_Error('paypal_api_error', $error_message);
    }
    
    // Get updated order details
    $updated_order = $this->get_order_details($paypal_order_id);
    
    if (is_wp_error($updated_order)) {
        $this->log_error('Failed to get updated order details: ' . $updated_order->get_error_message());
        return $updated_order;
    }
    
    $this->log_info('Successfully updated PayPal order with shipping details');
    
    return $updated_order;
}

}