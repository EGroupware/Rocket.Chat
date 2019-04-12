import { Match, check } from 'meteor/check';
import _ from 'underscore';
import { HTTP } from 'meteor/http';
import { ServiceConfiguration } from 'meteor/service-configuration';
import { OAuth } from 'meteor/oauth';
import { registerAccessTokenService } from './oauth';

function getIdentity(accessToken, config) {
	try {
		return HTTP.get(
			config.serverURL + config.identityPath,
			{
				headers: {
					Authorization: `Bearer ${ accessToken }`,
					Accept: 'application/json',
				},
			}).data;
	} catch (err) {
		throw _.extend(new Error(`Failed to fetch identity from custom OAuth ${ config.service }. ${ err.message }`), { response: err.response });
	}
}

// use RFC7662 OAuth 2.0 Token Introspection
function getTokeninfo(idToken, config) {
	try {
		const introspectPath = '/introspect';	// not yet configurable in Rocket.Chat, thought RFC defines that path
		return HTTP.post(
			config.serverURL + introspectPath,
			{
				auth: `${ config.clientId }:${ OAuth.openSecret(config.secret) }`,
				headers: {
					Accept: 'application/json',
				},
				params: {
					token: idToken,
					token_type_hint: 'access_token',
				},
			}).data;
	} catch (err) {
		throw _.extend(new Error(`Failed to fetch tokeninfo from custom OAuth ${ config.service }. ${ err.message }`), { response: err.response });
	}
}

registerAccessTokenService('custom', function(options) {
	check(options, Match.ObjectIncluding({
		accessToken: String,
		expiresIn: Match.Maybe(Match.Integer),
		scope: Match.Maybe(String),
		identity: Match.Maybe(Object),
	}));

	const config = ServiceConfiguration.configurations.findOne({ service: options.serviceName });
	let tokeninfo;
	if (!options.expiresIn || !options.scope) {
		try {
			tokeninfo = getTokeninfo(options.accessToken, config);
			// console.log('app/lib/server/oauth/custom.js: tokeninfo=', tokeninfo);
		} catch (err) {
			// ignore tokeninfo failures, as getIdentity still validates the token, we just dont know how long it's valid
			console.log(err);
		}
	}
	const identity = options.identity || getIdentity(options.accessToken, config);

	// support OpenID Connect /userinfo names
	if (typeof identity.profile_image_url === 'undefined' && identity.picture) {
		identity.profile_image_url = identity.picture;
	}
	if (typeof identity.lang === 'undefined' && identity.locale) {
		identity.profile_image_url = identity.picture;
	}

	const serviceData = {
		_OAuthCustom: true,
		accessToken: options.accessToken,
		expiresAt: tokeninfo.exp || (+new Date) + (1000 * parseInt(options.expiresIn, 10)),
		scope: options.scope || tokeninfo.scope || config.scope.split(/ /),
		id: identity[config.usernameField],
	};

	// only set the token in serviceData if it's there. this ensures
	// that we don't lose old ones (since we only get this on the first
	// log in attempt)
	if (options.refreshToken) {
		serviceData.refreshToken = options.refreshToken;
	}

	const whitelistedFields = [
		'name',
		'description',
		'profile_image_url',
		'profile_image_url_https',
		'lang',
		'email',
	];
	if (!whitelistedFields.includes(config.usernameField) && typeof serviceData[config.usernameField] === 'undefined') {
		whitelistedFields.push(config.usernameField);
	}
	const fields = _.pick(identity, whitelistedFields);
	_.extend(serviceData, fields);

	return {
		serviceData,
		options: {
			profile: {
				name: identity.name,
			},
		},
	};
});
