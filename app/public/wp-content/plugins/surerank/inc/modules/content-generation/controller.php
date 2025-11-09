<?php
/**
 * Content Generation Controller
 *
 * Main module controller for handling content generation functionality.
 *
 * @package SureRank\Inc\Modules\Content_Generation
 * @since 1.4.2
 */

namespace SureRank\Inc\Modules\Content_Generation;

use SureRank\Inc\Traits\Get_Instance;
use SureRank\Inc\Functions\Requests;
use SureRank\Inc\Modules\Ai_Auth\Controller as Ai_Auth_Controller;
use WP_Error;
use WP_Post;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Controller class
 *
 * Main module class for content generation functionality.
 */
class Controller {

	use Get_Instance;

	/**
	 * Credit System URL.
	 * 
	 * @var string
	 * @since 1.4.2
	 */
	private $api_url = 'https://credits.startertemplates.com/';

	/**
	 * Get API URL.
	 * 
	 * @return string API URL.
	 * @since 1.4.2
	 */
	public function get_api_url() {
		if ( ! defined( 'SURERANK_CREDIT_SERVER_API' ) ) {
			define( 'SURERANK_CREDIT_SERVER_API', $this->api_url );
		}

		return SURERANK_CREDIT_SERVER_API;
	}

	/**
	 * Generate Content for a given post.
	 * 
	 * @param array<string,string> $inputs Inputs for content generation.
	 * @param string               $type Type of content to generate (e.g., 'page_title').
	 * 
	 * @return string|WP_Error Generated content string or error object.
	 * @since 1.4.2
	 */
	public function generate_content( $inputs, $type = 'page_title' ) {
		$inputs = wp_parse_args(
			$inputs,
			[
				'page_title'    => '',
				'site_tagline'  => '',
				'site_name'     => '',
				'focus_keyword' => '',
			] 
		);

		$args = [
			'type'   => $type,
			'inputs' => $inputs,
			'source' => 'openai',
		];

		$response = $this->send_api_request( $args );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$response_body = wp_remote_retrieve_body( $response );

		$decoded_response = json_decode( $response_body, true );


		if ( ! is_array( $decoded_response ) ) {
			return new WP_Error( 'content_generation_error', __( 'Unable to generate content at this time. Please check your input and try again, or contact support if you need help.', 'surerank' ) );
		}

		if ( isset( $decoded_response['code'] ) ) {
			$code = $decoded_response['code'];
			/* translators: %s is response code */
			$message = isset( $decoded_response['message'] ) ? $decoded_response['message'] : sprintf( __( 'Failed to generate content with error code %s.', 'surerank' ), $code );

			$custom_error_messages = [
				'internal_server_error' => __( 'Something went wrong on our end. Please try again in a moment, or contact support if you need help.', 'surerank' ),
				'require_pro'           => __( 'You\'ve reached your free usage limit. Upgrade to Pro for additional credits to continue generating content.', 'surerank' ),
			];
			

			if ( isset( $custom_error_messages[ $code ] ) ) {
				$message = $custom_error_messages[ $code ];
			}

			return new WP_Error( $code, $message );
		}

		if ( ! isset( $decoded_response['content'] ) ) {
			return new WP_Error( 'content_generation_error', __( 'Unable to generate content at this time. Please try again, or contact support if you need help.', 'surerank' ) );
		}

		return $decoded_response['content'];
	}

	/**
	 * Send API request to content generation service.
	 *
	 * @since 1.4.2
	 * @param array<string, mixed> $request_data Request data.
	 * @return array<string, mixed>|WP_Error API response.
	 */
	private function send_api_request( $request_data ) {
		$auth_token = $this->get_auth_token();

		if ( empty( $auth_token ) || is_wp_error( $auth_token ) ) {
			return new WP_Error( 'no_auth_token', __( 'No authentication token found. Please connect your account.', 'surerank' ) );
		}

		$url = $this->get_api_url() . 'surerank/generate/content';

		$response = Requests::post(
			$url,
			[
				'headers' => array(
					'X-Token'      => base64_encode( $auth_token ),
					'Content-Type' => 'application/json; charset=utf-8',
				),
				'body'    => wp_json_encode( $request_data ),
				'timeout' => 30, // phpcs:ignore WordPressVIPMinimum.Performance.RemoteRequestTimeout.timeout_timeout
			] 
		);

		return $response;
	}

	/**
	 * Get Auth Token.
	 * 
	 * @since 1.4.2
	 * @return string|WP_Error
	 */
	public function get_auth_token() {
		$token = apply_filters( 'surerank_content_generation_auth_token', Ai_Auth_Controller::get_instance()->get_auth_data( 'user_email' ) );

		if ( empty( $token ) ) {
			$token = Ai_Auth_Controller::get_instance()->get_auth_data( 'user_email' );
		}
		
		return $token;
	}
}
