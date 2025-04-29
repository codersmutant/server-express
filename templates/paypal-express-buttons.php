<?php
/**
 * Template for PayPal Express Checkout Buttons
 * 
 * This template is served via an iframe to Website A for Express Checkout
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    // If accessed directly, return minimal HTML with error
    if (empty($_GET['rest_route'])) {
        echo '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>Direct access not allowed.</body></html>';
        exit;
    }
}

// Get parameters
$amount = isset($amount) ? $amount : (isset($_GET['amount']) ? sanitize_text_field($_GET['amount']) : '0.00');
$currency = isset($currency) ? $currency : (isset($_GET['currency']) ? sanitize_text_field($_GET['currency']) : 'USD');
$api_key = isset($api_key) ? $api_key : (isset($_GET['api_key']) ? sanitize_text_field($_GET['api_key']) : '');
$client_id = isset($client_id) ? $client_id : '';
$environment = isset($environment) ? $environment : 'sandbox';
$callback_url = isset($callback_url) ? $callback_url : (isset($_GET['callback_url']) ? sanitize_text_field($_GET['callback_url']) : '');
$site_url = isset($site_url) ? $site_url : (isset($_GET['site_url']) ? sanitize_text_field($_GET['site_url']) : '');

// Format amount for display
$formatted_amount = number_format((float)$amount, 2, '.', ',');
?><!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PayPal Express Checkout</title>
    
    <style>
        /* Basic reset */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;
            padding: 0;
            background-color: transparent;
        }
        
        /* Container */
        .container {
            width: 100%;
            position: relative;
        }
        
        /* PayPal buttons container */
        #paypal-express-button-container {
            width: 100%;
            min-height: 45px;
        }
        
        /* Messages */
        #express-message, 
        #express-error {
            margin: 10px 0;
            padding: 10px;
            border-radius: 4px;
            font-size: 14px;
            display: none;
        }
        
        #express-message {
            background-color: #f8f9fa;
            border: 1px solid #d6d8db;
            color: #1e2125;
        }
        
        #express-error {
            background-color: #f8d7da;
            border: 1px solid #f5c2c7;
            color: #842029;
        }
        
        /* Processing overlay */
        #express-processing {
            display: none;
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(255, 255, 255, 0.8);
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 10;
        }
        
        .spinner {
            width: 30px;
            height: 30px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #3498db;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 10px;
        }
        
        .processing-text {
            font-size: 14px;
            color: #333;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- PayPal Express buttons container -->
        <div id="paypal-express-button-container"></div>
        
        <!-- Message containers -->
        <div id="express-message"></div>
        <div id="express-error"></div>
        
        <!-- Processing overlay -->
        <div id="express-processing">
            <div class="spinner"></div>
            <div class="processing-text"><?php _e('Processing payment...', 'woo-paypal-proxy-server'); ?></div>
        </div>
    </div>
    
    <!-- Add hidden fields for JS -->
    <input type="hidden" id="api-key" value="<?php echo esc_attr($api_key); ?>">
    <input type="hidden" id="amount" value="<?php echo esc_attr($amount); ?>">
    <input type="hidden" id="currency" value="<?php echo esc_attr($currency); ?>">
    <input type="hidden" id="site-url" value="<?php echo esc_attr($site_url); ?>">
    <input type="hidden" id="callback-url" value="<?php echo esc_attr($callback_url); ?>">
    
    <?php if (!empty($client_id)) : ?>
    <!-- PayPal SDK -->
    <script src="https://www.paypal.com/sdk/js?client-id=<?php echo esc_attr($client_id); ?>&currency=<?php echo esc_attr($currency); ?>&intent=capture&components=buttons,messages,funding-eligibility&commit=true"></script>
    <?php endif; ?>
    
    <!-- Express Checkout script -->
    <script>
        // Store parent window origin if possible
        var parentOrigin = '*';
        var siteUrl = document.getElementById('site-url').value;
        
        if (siteUrl) {
            try {
                // Decode if it's base64 encoded
                if (siteUrl.indexOf('%') === -1 && /^[A-Za-z0-9+/=]+$/.test(siteUrl)) {
                    siteUrl = atob(siteUrl);
                } else {
                    siteUrl = decodeURIComponent(siteUrl);
                }
                
                var siteUrlObj = new URL(siteUrl);
                parentOrigin = siteUrlObj.origin;
            } catch (e) {
                console.error('Invalid site URL:', e);
            }
        }
        
        // Store order data
        var orderData = {
            orderId: null,
            amount: document.getElementById('amount').value || '0',
            currency: document.getElementById('currency').value || 'USD',
            apiKey: document.getElementById('api-key').value || '',
            callbackUrl: document.getElementById('callback-url').value || '',
        };
        
        // Store shipping address and options
        var shippingAddress = null;
        var shippingOptions = [];
        var selectedShippingOption = null;
        
        /**
         * Initialize PayPal Express buttons
         */
        function initExpressButtons() {
            // Check if PayPal SDK is available
            if (typeof paypal === 'undefined') {
                console.error('PayPal SDK not loaded');
                showError('PayPal SDK could not be loaded. Please try again later.');
                return;
            }
            
            // Notify parent window that buttons are loaded
            sendMessageToParent({
                action: 'button_loaded',
                status: 'success'
            });
            
            // Render PayPal Express buttons
            paypal.Buttons({
                // Style the buttons
                style: {
                    layout: 'horizontal',
                    color: 'gold',
                    shape: 'rect',
                    label: 'paypal',
                    tagline: false
                },
                
                // Create order
                createOrder: function(data, actions) {
                    console.log('PayPal Express button clicked, notifying parent window');
                    
                    // Notify parent window that button was clicked
                    sendMessageToParent({
                        action: 'button_clicked'
                    });
                    
                    // Wait for order data from parent
                    return new Promise(function(resolve, reject) {
                        console.log('Waiting for order data from parent window...');
                        
                        // Create message handler
                        var messageHandler = function(event) {
                            console.log('Received message from parent:', event.data);
                            
                            // Check if message is for us
                            var data = event.data;
                            if (!data || !data.action || data.source !== 'woocommerce-site') {
                                console.log('Not a valid message for us, ignoring');
                                return;
                            }
                            
                            // Handle create_paypal_order action
                            if (data.action === 'create_paypal_order') {
                                console.log('Received order data from parent');
                                
                                // Remove event listener
                                window.removeEventListener('message', messageHandler);
                                
                                // Store order data
                                orderData.orderId = data.order_id;
                                orderData.orderKey = data.order_key;
                                
                                console.log('Creating PayPal order with data:', orderData);
                                
                                // Create PayPal order
                                createPayPalOrder(orderData)
                                    .then(function(paypalOrderId) {
                                        console.log('PayPal order created:', paypalOrderId);
                                        resolve(paypalOrderId);
                                    })
                                    .catch(function(error) {
                                        console.error('Error creating PayPal order:', error);
                                        showError('Error creating PayPal order: ' + error.message);
                                        reject(error);
                                    });
                            } else if (data.action === 'order_creation_failed') {
                                console.log('Parent reported order creation failed');
                                
                                // Remove event listener
                                window.removeEventListener('message', messageHandler);
                                
                                // Show error
                                var error = new Error(data.message || 'Failed to create order');
                                showError('Order creation failed: ' + error.message);
                                reject(error);
                            } else if (data.action === 'shipping_options_updated') {
                                console.log('Received updated shipping options:', data);
                                
                                // Store shipping options for later use
                                shippingOptions = data.shipping_options || [];
                                selectedShippingOption = data.selected_option_id || null;
                                
                                // If we have an active order, update it with shipping options
                                if (data.order_id && actions.order) {
                                    try {
                                        actions.order.patch([
                                            {
                                                op: 'replace',
                                                path: '/purchase_units/@reference_id==default/amount',
                                                value: {
                                                    currency_code: orderData.currency,
                                                    value: data.order_total,
                                                    breakdown: {
                                                        item_total: {
                                                            currency_code: orderData.currency,
                                                            value: (data.order_total - data.shipping_total - data.tax_total).toFixed(2)
                                                        },
                                                        shipping: {
                                                            currency_code: orderData.currency,
                                                            value: data.shipping_total
                                                        },
                                                        tax_total: {
                                                            currency_code: orderData.currency,
                                                            value: data.tax_total
                                                        }
                                                    }
                                                }
                                            }
                                        ]);
                                    } catch (e) {
                                        console.error('Error updating order:', e);
                                    }
                                }
                            }
                        };
                        
                        // Add message listener
                        window.addEventListener('message', messageHandler);
                        
                        // Set timeout for order creation (30 seconds)
                        setTimeout(function() {
                            console.log('Timeout waiting for order data');
                            window.removeEventListener('message', messageHandler);
                            var error = new Error('Timeout waiting for order data');
                            showError('Timeout waiting for order data. Please try again.');
                            reject(error);
                        }, 30000);
                    });
                },
                
                // Handle shipping address change
// Handle shipping address change - COMPLETE REVISION
onShippingChange: function(data, actions) {
    console.log('Shipping address changed:', data);
    
    // Store the shipping address
    shippingAddress = data.shipping_address;
    
    // Notify parent window of address change
    sendMessageToParent({
        action: 'shipping_address_updated',
        payload: data
    });
    
    // Return a promise that resolves when we get shipping options
    return new Promise(function(resolve, reject) {
        // Create message handler for shipping options
        var messageHandler = function(event) {
            // Check if message is for us
            var messageData = event.data;
            if (!messageData || !messageData.action || messageData.source !== 'woocommerce-site') {
                return;
            }
            
            // Handle shipping_options_updated action
            if (messageData.action === 'shipping_options_updated') {
                console.log('Received updated shipping data:', messageData);
                
                // Remove event listener to prevent duplicate handlers
                window.removeEventListener('message', messageHandler);
                
                // Store shipping options
                var shippingOptions = messageData.shipping_options || [];
                var selectedOption = shippingOptions.length > 0 ? shippingOptions[0] : null;
                
                // Format for PayPal
                var paypalShippingOptions = [];
                if (selectedOption) {
                    paypalShippingOptions = [{
                        id: selectedOption.id,
                        label: selectedOption.label,
                        type: "SHIPPING",
                        selected: true,
                        amount: {
                            value: selectedOption.cost,
                            currency_code: orderData.currency
                        }
                    }];
                }
                
                // Prepare item data
                var items = [];
                if (messageData.items && messageData.items.length > 0) {
                    items = messageData.items.map(function(item) {
                        return {
                            name: item.name,
                            quantity: item.quantity,
                            unit_amount: {
                                currency_code: orderData.currency,
                                value: item.price
                            },
                            sku: item.sku || '',
                            description: item.description || ('Product ID: ' + item.product_id)
                        };
                    });
                }
                
                // Create the complete purchase unit replacement
                var patchPayload = [{
                    op: "replace",
                    path: "/purchase_units/@reference_id=='default'",
                    value: {
                        amount: {
                            value: messageData.order_total.toString(),
                            currency_code: orderData.currency,
                            breakdown: {
                                item_total: {
                                    currency_code: orderData.currency,
                                    value: messageData.subtotal.toString()
                                },
                                shipping: {
                                    currency_code: orderData.currency,
                                    value: messageData.shipping_total.toString()
                                },
                                tax_total: {
                                    currency_code: orderData.currency,
                                    value: messageData.tax_total.toString()
                                },
                                handling: {
                                    currency_code: orderData.currency,
                                    value: "0.00"
                                },
                                discount: {
                                    currency_code: orderData.currency,
                                    value: "0.00"
                                }
                            }
                        },
                        items: items,
                        shipping: {
                            options: paypalShippingOptions
                        },
                        reference_id: "default"
                    }
                }];
                
                console.log('Patching PayPal order with payload:', JSON.stringify(patchPayload));
                
                // Execute the patch
                actions.order.patch(patchPayload)
                    .then(function() {
                        console.log('Order patch successful');
                        resolve();
                    })
                    .catch(function(err) {
                        console.error('Error patching order:', err);
                        // Try to continue anyway
                        resolve();
                    });
            }
        };
        
        // Add message listener
        window.addEventListener('message', messageHandler);
        
        // Set timeout for shipping options (10 seconds)
        setTimeout(function() {
            console.log('Timeout waiting for shipping options');
            window.removeEventListener('message', messageHandler);
            // Default to approving the transaction
            resolve();
        }, 10000);
    });
},
                
                // On approval
                onApprove: function(data, actions) {
                    // Show processing message
                    showProcessing();
                    
                    // Capture the payment
                    return capturePayPalPayment(data.orderID)
                        .then(function(captureData) {
                            // Notify parent window
                            sendMessageToParent({
                                action: 'payment_approved',
                                payload: {
                                    orderID: data.orderID,
                                    transactionID: captureData.transaction_id,
                                    status: captureData.status,
                                    payer: data.payer,
                                    shipping_address: data.shipping_address
                                }
                            });
                            
                            // Show success message
                            hideProcessing();
                            showMessage('Payment successful! Finalizing your order...');
                        })
                        .catch(function(error) {
                            // Handle error
                            console.error('Error capturing payment:', error);
                            
                            // Notify parent window of error
                            sendMessageToParent({
                                action: 'payment_error',
                                error: {
                                    message: error.message || 'Payment failed'
                                }
                            });
                            
                            // Show error message
                            hideProcessing();
                            showError('Error capturing payment: ' + error.message);
                            
                            throw error;
                        });
                },
                
                // On cancel
                onCancel: function(data) {
                    console.log('Payment cancelled:', data);
                    
                    // Notify parent window
                    sendMessageToParent({
                        action: 'payment_cancelled',
                        payload: data
                    });
                    
                    showMessage('Payment cancelled. You can try again when you\'re ready.');
                },
                
                // On error
                onError: function(err) {
                    console.error('PayPal error:', err);
                    
                    // Notify parent window
                    sendMessageToParent({
                        action: 'payment_error',
                        error: {
                            message: err.message || 'An error occurred'
                        }
                    });
                    
                    showError('PayPal error: ' + (err.message || 'An error occurred'));
                }
            }).render('#paypal-express-button-container');
            
            // Check for container size and notify parent
            setTimeout(function() {
                var containerHeight = document.body.scrollHeight;
                sendMessageToParent({
                    action: 'resize_iframe',
                    height: containerHeight
                });
            }, 500);
        }
        
        /**
         * Create PayPal order via REST API
         */
        function createPayPalOrder(orderData) {
            return new Promise(function(resolve, reject) {
                // Calculate timestamp for security
                var timestamp = Math.floor(Date.now() / 1000);
                
                // Create request data
                var data = {
                    api_key: orderData.apiKey,
                    order_id: orderData.orderId,
                    amount: orderData.amount,
                    currency: orderData.currency,
                    timestamp: timestamp,
                    express_checkout: true
                };
                
                // Make the request
                fetch('/wp-json/wppps/v1/create-express-order', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                })
                .then(function(response) {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(function(responseData) {
                    if (!responseData.success) {
                        throw new Error(responseData.message || 'Failed to create PayPal order');
                    }
                    
                    // Return the PayPal order ID
                    resolve(responseData.order_id);
                })
                .catch(function(error) {
                    reject(error);
                });
            });
        }
        
        /**
         * Capture PayPal payment via REST API
         */
        function capturePayPalPayment(paypalOrderId) {
            return new Promise(function(resolve, reject) {
                // Calculate timestamp for security
                var timestamp = Math.floor(Date.now() / 1000);
                
                // Create request data
                var data = {
                    api_key: orderData.apiKey,
                    paypal_order_id: paypalOrderId,
                    order_id: orderData.orderId,
                    timestamp: timestamp,
                    express_checkout: true
                };
                
                // Make the request
                fetch('/wp-json/wppps/v1/capture-payment', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                })
                .then(function(response) {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(function(responseData) {
                    if (!responseData.success) {
                        throw new Error(responseData.message || 'Failed to capture payment');
                    }
                    
                    // Return the capture data
                    resolve(responseData);
                })
                .catch(function(error) {
                    reject(error);
                });
            });
        }
        
        /**
         * Send message to parent window
         */
        function sendMessageToParent(message) {
            // Add source identifier
            message.source = 'paypal-proxy';
            
            // Send message
            window.parent.postMessage(message, parentOrigin);
        }
        
        /**
         * Show error message
         */
        function showError(message) {
            var errorElement = document.getElementById('express-error');
            if (errorElement) {
                errorElement.textContent = message;
                errorElement.style.display = 'block';
            }
        }
        
        /**
         * Show success message
         */
        function showMessage(message) {
            var messageElement = document.getElementById('express-message');
            if (messageElement) {
                messageElement.textContent = message;
                messageElement.style.display = 'block';
            }
        }
        
        /**
         * Show processing overlay
         */
        function showProcessing() {
            var processingElement = document.getElementById('express-processing');
            if (processingElement) {
                processingElement.style.display = 'flex';
            }
        }
        
        /**
         * Hide processing overlay
         */
        function hideProcessing() {
            var processingElement = document.getElementById('express-processing');
            if (processingElement) {
                processingElement.style.display = 'none';
            }
        }
        
        /**
         * Initialize when DOM is ready
         */
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initExpressButtons);
        } else {
            initExpressButtons();
        }
        
        // Watch for DOM changes and update iframe size accordingly
        var resizeObserver = new ResizeObserver(function(entries) {
            for (var entry of entries) {
                var height = entry.contentRect.height || document.body.scrollHeight;
                sendMessageToParent({
                    action: 'resize_iframe',
                    height: height
                });
            }
        });
        
        // Observe the body element
        document.addEventListener('DOMContentLoaded', function() {
            resizeObserver.observe(document.body);
        });
    </script>
</body>
</html>