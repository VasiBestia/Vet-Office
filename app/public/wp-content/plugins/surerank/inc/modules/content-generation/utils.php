<?php
/**
 * Content Generation Utils
 *
 * Utils module class for handling content generation functionality.
 *
 * @package SureRank\Inc\Modules\Content_Generation
 * @since 1.4.2
 */

namespace SureRank\Inc\Modules\Content_Generation;

use SureRank\Inc\Traits\Get_Instance;
use SureRank\Inc\Modules\FixSeoChecks\Page as FixSeoPage;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Utils class
 *
 * Main module class for content generation functionality.
 */
class Utils {

	use Get_Instance;

	/**
	 * Get API types.
	 * 
	 * @return array<int,string> Array of API types.
	 * @since 1.4.2
	 */
	public function get_api_types() {
		return apply_filters(
			'surerank_content_generation_types',
			[
				'page_title',
				'home_page_title',
				'page_description',
				'home_page_description',
				'social_title',
				'social_description',
				'site_tag_line',
				'page_url_slug',
			]
		);
	}

	/**
	 * Prepare inputs for content generation.
	 *
	 * @param int|null $id Post or term ID (optional).
	 * @param bool     $is_taxonomy Whether the ID is for a taxonomy term.
	 * @return array<string,string> Array of inputs for content generation.
	 * @since 1.4.2
	 */
	public function prepare_content_inputs( $id = null, $is_taxonomy = false ) {
		$title = '';

		if ( ! empty( $id ) ) {
			if ( $is_taxonomy ) {
				$term = get_term( $id );
				if ( $term && ! is_wp_error( $term ) ) {
					$title = $term->name;
				}
			} else {
				$post = get_post( $id );
				if ( $post ) {
					$title = get_the_title( $id );
				}
			}
		}

		return apply_filters(
			'surerank_content_generation_inputs',
			[
				'site_name'     => get_bloginfo( 'name' ),
				'site_tagline'  => get_bloginfo( 'description' ),
				'page_title'    => $title,
				'focus_keyword' => $this->get_focus_keyword( $id, $is_taxonomy ),
			]
		);
	}

	/**
	 * Get focus keyword for the post or term.
	 *
	 * @param int|null $post_id Post ID or Term ID.
	 * @param bool     $is_taxonomy Whether it's a taxonomy term.
	 * @return string Focus keyword.
	 * @since 1.4.2
	 */
	private function get_focus_keyword( $post_id = null, $is_taxonomy = false ) {
		if ( empty( $post_id ) ) {
			return '';
		}

		if ( $is_taxonomy ) {
			$term_meta = get_term_meta( $post_id, 'surerank_settings_general', true );
			return $term_meta['focus_keyword'] ?? '';
		}

		$post_meta = get_post_meta( $post_id, 'surerank_settings_general', true );
		return $post_meta['focus_keyword'] ?? '';
	}


}
