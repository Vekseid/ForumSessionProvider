<?php
/****************************************************************************
 * Elkarte/SMF-MediaWiki Single-Sign-On
 * @Author Vekseid (vekseid@elliquiy.com)
 * @license BSD https://opensource.org/licenses/BSD-3-Clause
 *	 (See LICENCE.md file)
 *
 * Uses MediaWiki's SessionManager functionality to have the forum control
 * when a user is logged in. Defaults to and originally written for Elkarte
 * (https://www.elkarte.net) - extended to support SMF and hopefully any SMF
 * fork eventually.
 *
 * Some code under copyright by Simple Machines (https://simplemachines.org/)
 * https://github.com/SimpleMachines/smf-mw-auth/blob/master/Auth_SMF.php
 ****************************************************************************/

use MediaWiki\MediaWikiServices;
use MediaWiki\Session\ImmutableSessionProviderWithCookie;
use MediaWiki\Session\UserInfo;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\Auth\TemporaryPasswordPrimaryAuthenticationProvider;

class ForumAuthManager extends TemporaryPasswordPrimaryAuthenticationProvider
{
    public function __construct( $params = [] ) {
        parent::__construct( $params );
    }

    public function setConfig( \Config $config ) {
        parent::setConfig( $config );
    }

    protected function getPasswordResetData( $username, $data ) {
        return false;
    }

    public function getAuthenticationRequests( $action, array $options ) {
    }

    /*
     * This is implanted just to disable password changes.
    */
    public function providerAllowsAuthenticationDataChange(
        MediaWiki\Auth\AuthenticationRequest $req, $checkData = true
    ) {
        $rest = \StatusValue::newGood();
        $rest->setOK(false);
        return $rest;
    }

    /*
     * This one disables any other properties we need to block
    */
    public function providerAllowsPropertyChange( $property )
    {
        if (in_array($property, array(
            'emailaddress'
        )))
            return false;
        return true;
    }
}