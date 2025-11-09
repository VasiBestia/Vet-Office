import PageContentWrapper from '@AdminComponents/page-content-wrapper';
import { __, sprintf } from '@wordpress/i18n';
import { Button, toast } from '@bsf/force-ui';
import { useSuspenseSelect } from '@wordpress/data';
import { STORE_NAME } from '@AdminStore/constants';
import withSuspense from '@AdminComponents/hoc/with-suspense';
import { LoaderCircle, ExternalLink, RefreshCw } from 'lucide-react';
import { Tooltip } from '@AdminComponents/tooltip';
import GeneratePageContent from '@Functions/page-content-generator';
import { cn } from '@/functions/utils';
import { createLazyRoute } from '@tanstack/react-router';
import { applyFilters } from '@wordpress/hooks';
import { useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

const xmlContent = [
	{
		type: 'switch',
		id: 'enable_xml_sitemap',
		storeKey: 'enable_xml_sitemap',
		dataType: 'boolean',
		label: __( 'Enable XML Sitemap', 'surerank' ),
		description: __(
			'Generates an XML sitemap to help search engines index your site content.',
			'surerank'
		),
	},
	{
		type: 'switch',
		id: 'enable_xml_image_sitemap',
		storeKey: 'enable_xml_image_sitemap',
		dataType: 'boolean',
		label: __( 'Include Images in XML Sitemap', 'surerank' ),
		description: __(
			'Add images from your posts and pages to the XML sitemap so search engines can find and index them more easily. Images are visible only in source code.',
			'surerank'
		),
		disabled: ( formValues ) => {
			return ! formValues.enable_xml_sitemap;
		},
	},
];

const xmlScreen = applyFilters(
	'surerank-pro.sitemap-settings',
	[
		{
			container: null,
			content: [
				{
					id: 'xml-settings',
					type: 'title',
					label: __( 'XML', 'surerank' ),
				},
			],
		},
		{
			container: null,
			content: xmlContent,
		},
	],
	xmlContent
);

export const PAGE_CONTENT = [
	//This is the very first depth of the form. And it represents the section container of the form.
	{
		container: {
			id: 'xml-settings-container',
			direction: 'column',
			gap: 6,
		},
		content: xmlScreen,
	},
];

const SiteMaps = () => {
	const { metaSettings } = useSuspenseSelect( ( select ) => {
		const { getMetaSettings } = select( STORE_NAME );
		return {
			metaSettings: getMetaSettings(),
		};
	}, [] );

	const SitemapButtons = () => {
		const [ isGenerating, setIsGenerating ] = useState( false );
		const [ progress, setProgress ] = useState( 0 );
		const [ currentItem, setCurrentItem ] = useState( '' );
		const isDisabled = ! metaSettings.enable_xml_sitemap;

		const generateCache = async () => {
			setIsGenerating( true );
			setProgress( 0 );
			setCurrentItem( '' );

			try {
				const cronsAvailable = surerank_admin_common?.crons_available;

				if ( cronsAvailable ) {
					// For cron-based generation, don't set currentItem or progress
					const result = await apiFetch( {
						path: '/surerank/v1/sitemap/generate-cache',
						method: 'POST',
					} );

					toast.warning( result.message, {
						description: result.description,
						icon: <LoaderCircle className="animate-spin" />,
					} );
				} else {
					// Use manual batch processing
					toast.warning(
						__( 'Sitemap cache generation started…', 'surerank' ),
						{
							description: __(
								'Processing items in batches it will take some time, please stay on the page.',
								'surerank'
							),
							icon: <LoaderCircle className="animate-spin" />,
						}
					);

					//prepare
					const response = await apiFetch( {
						path: '/surerank/v1/prepare-cache',
						method: 'GET',
					} );

					const items = response.data;

					for ( let i = 0; i < items.length; i++ ) {
						const item = items[ i ];
						const progressPercentage = Math.round( ( ( i + 1 ) / items.length ) * 100 );

						// Set current item being processed
						setCurrentItem( `${ item.type }: ${ item.slug }` );
						setProgress( progressPercentage );

						await apiFetch( {
							path: '/surerank/v1/sitemap/generate-cache-manual',
							method: 'POST',
							data: {
								page: item.page,
								slug: item.slug,
								type: item.type,
							},
						} );
					}

					toast.success(
						__( 'Sitemap cache generation completed!', 'surerank' ),
						{
							description: __(
								'All content has been processed successfully.',
								'surerank'
							),
						}
					);
				}
			} catch ( error ) {
				toast.error(
					error.message ||
						__(
							'Error generating sitemap cache. Please try again.',
							'surerank'
						)
				);
			} finally {
				setIsGenerating( false );
				setProgress( 0 );
				setCurrentItem( '' );
			}
		};

		return (
			<>
				<Tooltip
					className="max-w-[18rem]"
					content={ ( () => {
						if ( ! isGenerating ) {
							return __( 'Generate sitemap cache', 'surerank' );
						}
						if ( currentItem ) {
							return sprintf(
								/* translators: 1: content type, 2: progress percentage */
								__( 'Cache generation in progress for %1$s (%2$s%%)', 'surerank' ),
								currentItem,
								progress
							);
						}
						return __( 'Sitemap cache generation is in progress…', 'surerank' );
					} )() }
					arrow
				>
					<Button
						variant="outline"
						size="md"
						className={ cn( 'min-w-fit flex items-center gap-2', {
							'cursor-not-allowed': isDisabled,
						} ) }
						disabled={ isDisabled || isGenerating }
						onClick={ generateCache }
						icon={
							<RefreshCw
								className={ cn( {
									'animate-spin': isGenerating,
								} ) }
							/>
						}
						iconPosition="right"
					>
						{ isGenerating
							? __( 'Generating…', 'surerank' )
							: __( 'Generate Cache', 'surerank' ) }
					</Button>
				</Tooltip>
				<Tooltip
					className="max-w-[18rem]"
					content={
						isDisabled
							? __(
									'Sitemap is currently disabled. Please enable XML sitemap in settings to access the sitemap file.',
									'surerank'
							  )
							: ''
					}
					arrow
				>
					<Button
						variant="outline"
						size="md"
						className={ cn( 'min-w-fit flex items-center gap-2', {
							'cursor-not-allowed':
								! metaSettings.enable_xml_sitemap,
						} ) }
						disabled={ isDisabled }
						onClick={
							metaSettings.enable_xml_sitemap
								? () =>
										window.open(
											surerank_admin_common?.sitemap_url,
											'_blank',
											'noopener,noreferrer'
										)
								: undefined
						}
						icon={ <ExternalLink /> }
						iconPosition="right"
					>
						{ __( 'Open Sitemap', 'surerank' ) }
					</Button>
				</Tooltip>
			</>
		);
	};

	return (
		<PageContentWrapper
			title={ __( 'Sitemaps', 'surerank' ) }
			secondaryButton={ <SitemapButtons /> }
			description={ __(
				'Generates a sitemap to help search engines find and index your content more efficiently. Showing image count can improve how your media appears in search results.',
				'surerank'
			) }
		>
			<GeneratePageContent json={ PAGE_CONTENT } />
		</PageContentWrapper>
	);
};

export const LazyRoute = createLazyRoute( '/advanced/sitemaps' )( {
	component: withSuspense( SiteMaps ),
} );

export default withSuspense( SiteMaps );
