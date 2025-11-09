import { Container, Text } from '@bsf/force-ui';
import { __ } from '@wordpress/i18n';
import { cn } from '@Functions/utils';

const EmptyState = ( { message, className } ) => (
	<Container
		align="center"
		justify="center"
		className={ cn(
			'p-8 bg-background-primary border border-solid border-border-subtle rounded-lg',
			className
		) }
	>
		<Text size={ 14 } weight={ 400 } color="secondary">
			{ message || __( 'No data available', 'surerank' ) }
		</Text>
	</Container>
);

export default EmptyState;
