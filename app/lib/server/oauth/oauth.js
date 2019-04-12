import { Meteor } from 'meteor/meteor';
import { Match, check } from 'meteor/check';
import { Accounts } from 'meteor/accounts-base';
import { ServiceConfiguration } from 'meteor/service-configuration';
import _ from 'underscore';

const AccessTokenServices = {};

export const registerAccessTokenService = function(serviceName, handleAccessTokenRequest) {
	AccessTokenServices[serviceName] = {
		serviceName,
		handleAccessTokenRequest,
	};
};

// Listen to calls to `login` with an oauth option set. This is where
// users actually get logged in to meteor via oauth.
Accounts.registerLoginHandler(function(options) {
	if (!options.accessToken) {
		return undefined; // don't handle
	}

	check(options, Match.ObjectIncluding({
		serviceName: String,
	}));

	// Check if service is configured and therefore a custom OAuth
	const config = ServiceConfiguration.configurations.findOne({ service: options.serviceName });

	let service = AccessTokenServices[options.serviceName];

	if (!service && config) {
		service = AccessTokenServices.custom;
	}

	// Skip everything if there's no service set by the oauth middleware
	if (!service) {
		throw new Error(`Unexpected AccessToken service ${ options.serviceName }`);
	}

	// Make sure we're configured
	if (!config) {
		throw new ServiceConfiguration.ConfigError();
	}

	if (!_.contains(Accounts.oauth.serviceNames(), options.serviceName)) {
		// serviceName was not found in the registered services list.
		// This could happen because the service never registered itself or
		// unregisterService was called on it.
		return {
			type: 'oauth',
			error: new Meteor.Error(
				Accounts.LoginCancelledError.numericError,
				`No registered oauth service found for: ${ options.serviceName }`
			),
		};
	}

	const oauthResult = service.handleAccessTokenRequest(options);

	return Accounts.updateOrCreateUserFromExternalService(options.serviceName, oauthResult.serviceData, oauthResult.options);
});


