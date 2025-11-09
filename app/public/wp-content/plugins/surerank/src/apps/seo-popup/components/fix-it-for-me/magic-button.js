import { SparklesIconSolid, ReloadIcon } from '@GlobalComponents/icons';
import { useDispatch, useSelect } from '@wordpress/data';
import { Button } from '@bsf/force-ui';
import { STORE_NAME } from '@/store/constants';
import { cn } from '@/functions/utils';

const MagicButton = ( { fieldKey, onUseThis } ) => {
	const { currentScreen, currentTab, currentMetaTab, generatedContents } =
		useSelect( ( select ) => {
			const selector = select( STORE_NAME );

			return {
				...selector.getPageSeoChecks(),
				...selector.getAppSettings(),
			};
		}, [] );
	const { updateAppSettings } = useDispatch( STORE_NAME );

	// Check if content has been generated for this field
	const hasGeneratedContent =
		generatedContents &&
		generatedContents[ fieldKey ] &&
		generatedContents[ fieldKey ].length > 0;

	const handleClick = () => {
		const updatedGeneratedContents = { ...generatedContents };
		if ( updatedGeneratedContents[ fieldKey ] ) {
			delete updatedGeneratedContents[ fieldKey ];
		}

		updateAppSettings( {
			currentScreen: 'fixItForMe',
			previousScreen: currentScreen,
			previousTab: currentTab,
			previousMetaTab: currentMetaTab,
			selectedFieldKey: fieldKey,
			onUseThis,
			generateContentProcess: 'idle',
			generatedContents: updatedGeneratedContents,
			error: null,
		} );
	};

	return (
		<Button
			size="xs"
			variant="ghost"
			className={ cn(
				'p-0.5 text-icon-interactive outline-brand-200 rounded-sm',
				hasGeneratedContent && '[&>svg]:size-3 p-1'
			) }
			icon={
				hasGeneratedContent ? <ReloadIcon /> : <SparklesIconSolid />
			}
			onClick={ handleClick }
		/>
	);
};

export default MagicButton;
