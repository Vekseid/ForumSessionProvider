<?php
/****************************************************************************
 * Elkarte/SMF-MediaWiki Single-Sign-On
 * @Author Vekseid (vekseid@elliquiy.com)
 * @license BSD https://opensource.org/licenses/BSD-3-Clause
 *     (See LICENCE.md file)
 *
 * Uses MediaWiki's SessionManager functionality to have the forum control
 * when a user is logged in. Defaults to and originally written for Elkarte
 * (https://www.elkarte.net) - extended to support SMF and hopefully any SMF
 * fork eventually.
 *
 * Some code under copyright by Simple Machines (https://simplemachines.org/)
 * https://github.com/SimpleMachines/smf-mw-auth/blob/master/Auth_SMF.php
 ****************************************************************************/

use MediaWiki\Session\ImmutableSessionProviderWithCookie;
use MediaWiki\Session\UserInfo;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Logger\LoggerFactory;

class ForumSessionProvider extends ImmutableSessionProviderWithCookie {

	protected $loaded = false;
	protected $logger;
	protected $id = 0;
	protected $password = '';
	protected $authSecret = false;
	protected $prefix;
	protected $db;
	protected $dbtype;
	protected $userForum;
	protected $userWiki;
	protected $userInfo;
    protected $userName;
    protected $groups = [];
	
	public function __construct( array $params = [] ) {
		parent::__construct($params);

		// TODO: Keep eye out for other things that need logging. Admin changes?
		$this->logger = LoggerFactory::getInstance('ForumSessionProviderLog');

        // Administrator always get admin rights.
        if (!in_array(1, $GLOBALS['wgFSPAdminGroups']))
            $GLOBALS['wgFSPAdminGroups'][] = 1;

        if (!in_array(1, $GLOBALS['wgFSPInterfaceGroups']))
            $GLOBALS['wgFSPInterfaceGroups'][] = 1;
		
		if (is_readable($GLOBALS['wgFSPPath'] . '/Settings.php')) {
		    require ($GLOBALS['wgFSPPath'] . '/Settings.php');
		    // Globals declared in Settings.php gain local scope.
		    $GLOBALS['wgFSPCookieName'] = $cookiename;
		    $GLOBALS['wgFSPBoardURL'] = $boardurl;

			$this->decodeCookie();

			if ($this->id && is_integer($this->id)) {
                $this->prefix = $db_prefix;

                if (empty($cookie_no_auth_secret) && !empty($auth_secret)) {
                    $this->authSecret = $auth_secret;
                }

                // TODO: make use of $db_type to support other databases.
                $this->dbtype = $db_type;

                $this->db = new mysqli($db_server, $db_user, $db_passwd, $db_name);

                if (!$this->db->connect_error) {
                    $this->loaded = true;
                }
                else {
                    $this->logger->warning('MySQL Error: ' . $this->db->connect_error);
                }
            }
		}
		else {
		    $this->logger->warning('Settings.php missing or not readable. Tried to load: ' . $GLOBALS['wgFSPPath'] . '/Settings.php');
        }
	}

	private function decodeCookie() {
        switch ($GLOBALS['wgFSPSoftware']) {
            case 'elk1.0':
            case 'elk1.1':
            case 'smf2.1':
                list($this->id, $this->password) = json_decode($_COOKIE[$GLOBALS['wgFSPCookieName']]);
                break;
            case 'smf2.0':
                list($this->id, $this->password) = unserialize($_COOKIE[$GLOBALS['wgFSPCookieName']]);
                break;
            default: return;
        }

        $this->id = (int) $this->id;
        $this->password = (string) $this->password;
    }

    /**
     * @param $special
     * @param $subPage
     *
     * Most previous handlers have either been depreciated or don't work with the session-based concept.
     *
     * SpecialPageBeforeExecute serves the same purpose.
     *
     * TODO: Workout session data properly so logouts and redirects actually happen.
     */
    public static function onSpecialPageBeforeExecute( $special, $subPage ) {
        // The case of some of these isn't always consistent with what shows up in the url.
	    switch (strtolower($special->getName())) {
            case 'createaccount':
                ForumSessionProvider::redirect('register');
                break;
            case 'userlogin':
                ForumSessionProvider::redirect('login');
                break;
            case 'userlogout':
                ForumSessionProvider::redirect('logout');
                break;
        }
    }

	public static function redirect($action) {
        header ('Location: '.$GLOBALS['wgFSPBoardURL'].'/index.php?action='.$action);
        exit();
    }

    private function checkPassword() {
        switch ($GLOBALS['wgFSPSoftware']) {
            case 'elk1.0':
            case 'elk1.1':
                return $this->password === hash('sha256', $this->userForum['passwd'] . $this->userForum['password_salt']);
                break;
            case 'smf2.0':
                if ($this->authSecret !== false) {
                    return $this->userForum['passwd'] === hash_hmac('sha1', sha1($this->userForum['passwd'] . $this->userForum['password_salt']), $this->authSecret);
                }
                else {
                    return $this->password === sha1($this->userForum['passwd'] . $this->userForum['password_salt']);
                }
                break;
            case 'smf2.1':
                return $this->password === hash('sha512', $this->userForum['passwd'] . $this->userForum['password_salt']);
                break;
            default: return false;
        }
    }
	
    public function provideSessionInfo( WebRequest $request ) {
	    if (!$this->loaded) {
	        return null;
        }

        $result = $this->db->query("
                SELECT member_name, email_address, real_name, passwd, password_salt, id_group, additional_groups
                FROM {$this->prefix}members
                WHERE id_member = '{$this->id}' AND is_activated = 1
                LIMIT 1
            ");

        $this->userForum = $result->fetch_assoc();
        $result->free();

        if (empty($this->userForum)) {
            $this->logger->warning('Member id not found in forum database: ' . $this->id);
            return null;
        }

        if ($this->checkPassword()) {
            $this->userName = ucfirst($this->userForum['member_name']);

            switch (strtolower($GLOBALS['wgFSPNameStyle'])) {
                case 'smf':
                    // Generally backwards compatible with former SMF/Elkarte Auth plugins.
                    $this->userName = str_replace('_', '\'', $this->userName);
                    $this->userName = strtr($this->userName, array('[' => '=', ']' => '"', '|' => '&', '#' => '\\', '{' => '==', '}' => '""', '@' => '&&', ':' => '\\\\'));
                    break;
                case 'domain':
                    // A more restrictive policy.
                    if ($this->userName !== preg_replace('`[^a-zA-Z0-9 .-]+`i', '', $this->userName)) {
                        $this->logger->warning('Member failed to validate domain pattern: ' . $this->id);
                        return null;
                    }
                    break;
                default:
                    // Just kick them if they have an unusable username.
                    if (preg_match('`[#<>[\]|{}@:]+`', $this->userName)) {
                        $this->logger->warning('Member with invalid name: ' . $this->id);
                        return null;
                    }
            }

        }
        else {
            $this->logger->warning('Member ID ' . $this->id . ' failed to validate. Remote IP:' . $_SERVER['REMOTE_ADDR']);
            return null;
        }

        if (strlen($this->userForum['additional_groups'])) {
            $this->groups = explode(',', $this->userForum['additional_groups']);
        }
        $this->groups[] = $this->userForum['id_group'];

        $this->userInfo = UserInfo::newFromName($this->userName, true);
        $this->userWiki = $this->userInfo->getUser();

        if (!($this->userWiki->isLoggedIn() && $this->userWiki->getName() === $this->userName)) {
            $this->userWiki->setId($this->userWiki->idFromName($this->userName));

            if ($this->userWiki->getID() === 0) {
                $this->createWikiUser();
            }
        }

        // Toggle special permissions immediately if they have changed.
        $this->setWikiGroups();

        /**
         * The forum is responsible for e-mails, so we don't need to worry about it changing much.
         */
        if (time() > ((int) $this->userWiki->getOption('forum_last_update_user', 0) + 1800)) {
            $this->updateWikiUser();
        }

        if ((!array_intersect($GLOBALS['wgFSPAllowGroups'], $this->groups) ||
                array_intersect($GLOBALS['wgFSPDenyGroups'], $this->groups) ||
                $this->isBanned()) &&
                !array_intersect($GLOBALS['wgFSPAdminGroups'], $this->groups) &&
                !array_intersect($GLOBALS['wgFSPSuperGroups'], $this->groups)) {
            $this->logger->warning('Member denied access: ' . $this->id);
            return null;
        }

        if ($this->sessionCookieName === null) {
            $id = $this->hashToSessionId($this->userName);
            $persisted = false;
            $forceUse = true;
        } else {
            $id = $this->getSessionIdFromCookie($request);
            $persisted = $id !== null;
            $forceUse = false;
        }

        return new SessionInfo( SessionInfo::MAX_PRIORITY, [
            'provider' => $this,
            'id' => $id,
            'userInfo' => $this->userInfo,
            'persisted' => $persisted,
            'forceUse' => $forceUse,
        ] );
    }

    private function updateWikiUser() {
	    $this->userWiki->setEmail($this->userForum['email_address']);
        $this->userWiki->setRealName($this->userForum['real_name']);

        if ($this->userWiki->getOption('forum_member_id', 0) === 0) {
            $this->userWiki->setOption('forum_member_id', $this->id);
        }

        $this->userWiki->setOption('forum_last_update_user', time());
        $this->userWiki->saveSettings();
    }

    private function setWikiGroups() {
        // Wiki Group Name => Forum Group IDS
        $groupActions = [
            'sysop' => $GLOBALS['wgFSPAdminGroups'],
            'interface-admin' => $GLOBALS['wgFSPInterfaceGroups'],
            'bureaucrat' => $GLOBALS['wgFSPSuperGroups'],
        ];

        // Add in our special groups.
        if (is_array($GLOBALS['wgFSPSpecialGroups'])) {
            foreach ($GLOBALS['wgFSPSpecialGroups'] as $fs_group_id => $wiki_group_name) {
                // Group didn't exist?
                if (!isset($groupActions[$wiki_group_name]))
                    $groupActions[$wiki_group_name] = [];

                // Add the Forum group into the wiki group.
                $groupActions[$wiki_group_name][] = $fs_group_id;
            }
        }

        // Now we are going to check all the groups.
        foreach ($groupActions as $wiki_group_name => $fs_group_ids) {
            // They are in the Forum group but not the wiki group?
            if (array_intersect($fs_group_ids, $this->groups) && !in_array($wiki_group_name, $this->userWiki->getEffectiveGroups()))
                $this->userWiki->addGroup($wiki_group_name);
            // They are not in the Forum group, but in the wiki group
            elseif (!array_intersect($fs_group_ids, $this->groups) && in_array($wiki_group_name, $this->userWiki->getEffectiveGroups()))
                $this->userWiki->removeGroup($wiki_group_name);
        }

        // Did we make any changes?
        $this->userWiki->setOption('forum_last_update_groups', time());
        $this->userWiki->saveSettings();
    }

    private function createWikiUser() {
        $this->userWiki->setName($this->userName);
        $this->userWiki->setEmail($this->userForum['email_address']);
        $this->userWiki->setRealName($this->userForum['real_name']);
        $this->userWiki->mEmailAuthenticated = wfTimestampNow();

        $this->userWiki->addToDatabase();

        $this->userWiki->setOption('forum_last_update_user', time());
        $this->userWiki->saveSettings();
    }

    private function isBanned() {
        // Check their ban once every 5 minutes.
        if (!$GLOBALS['wgFSPEnableBanCheck']) {
            return false;
        }

        if (!(time() > ((int) $this->userWiki->getOption('forum_last_update_ban', 0) + 300)))
            return $this->userWiki->getOption('forum_is_banned', 0);

        switch ($GLOBALS['wgFSPSoftware']) {
            case 'elk1.0':
            case 'elk1.1':
            case 'smf2.0':
            case 'smf2.1':
                return $this->isBannedSMF();
                break;
            default: return false;
        }
    }

    private function isBannedSMF() {
        $result = $this->db->query('
			SELECT id_ban
			FROM ' . $this->prefix . 'ban_items AS i
			LEFT JOIN ' . $this->prefix . 'ban_groups AS g
				ON (i.id_ban_group = g.id_ban_group)
			WHERE i.id_member = ' . ( (int) $this->id) . '
				AND (g.cannot_post = 1 OR g.cannot_login = 1)');

        $banned = $result->num_rows;
        $result->free();

        $this->userWiki->setOption('forum_last_update_ban', time());
        $this->userWiki->setOption('forum_is_banned', $banned);
        $this->userWiki->saveSettings();

        return $banned;
    }
}