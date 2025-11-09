import { __ } from '@wordpress/i18n';
import { Button, Text } from '@bsf/force-ui';
import { SparklesIcon } from '@GlobalComponents/icons';

/**
 * UpgradeCpt Component
 *
 * Props:
 *  - onClickUpgrade?: function
 *      Optional callback invoked when the "Upgrade Now" button is clicked.
 *      If not provided, the component will attempt to open the global pricing link
 *      (window.surerank_globals.pricing_link) in a new tab as a sensible default.
 * Example:
 *  <UpgradeCpt onClickUpgrade={() => window.open(pricingUrl, '_blank')} />
 * @param {Object}   props                Component props
 * @param {Function} props.onClickUpgrade Optional callback for upgrade button click
 * @return {JSX.Element}                      Rendered component
 */
const UpgradeCpt = ( { onClickUpgrade } ) => {
	const handleUpgradeClick = () => {
		if ( typeof onClickUpgrade !== 'function' ) {
			const pricingLink = window?.surerank_globals?.pricing_link;
			if ( pricingLink ) {
				window.open( pricingLink, '_blank', 'noopener' );
			}
			return;
		}
		onClickUpgrade();
	};
	return (
		<div className="bg-background-secondary rounded-lg p-2">
			<div className="bg-background-primary rounded-md p-4 flex flex-col items-center gap-3">
				<SparklesIcon className="text-text-primary" />
				<div className="text-center">
					<Text as="h3" size={ 16 } weight={ 600 } color="primary">
						{ __( 'AI Credits Exhausted', 'surerank' ) }
					</Text>
					<Text color="secondary" className="mt-1">
						{ __(
							"You've used all your available AI credits. To keep generating titles, descriptions, and more with AI, please purchase additional credits.",
							'surerank'
						) }
					</Text>
				</div>
				<Button
					variant="primary"
					size="md"
					onClick={ handleUpgradeClick }
				>
					{ __( 'Upgrade Now', 'surerank' ) }
				</Button>
			</div>
		</div>
	);
};

export default UpgradeCpt;
