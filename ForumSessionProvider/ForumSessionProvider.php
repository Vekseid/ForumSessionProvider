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
    protected $password = '';
    protected $authSecret = false;
    protected $prefix;

    /** @var PDO $db */
    protected $db;
    protected $debug;
    protected $databaseDriver;
    protected $cookieName;
    protected $userId = 0;
    protected $userForum;
    protected $userWiki;
    protected $userInfo;
    protected $userName;
    protected $userGroups = [];

    public function __construct( array $params = [] ) {
        parent::__construct($params);

        // TODO: Keep eye out for other things that need logging. Admin changes?
        $this->logger = LoggerFactory::getInstance('ForumSessionProvider');

        if (!empty($GLOBALS['wgFSPDebug'])) {
            $this->debug = true;
            $this->logger->info('Constructor initialized, debug log enabled.');
        }

        // This is old Auth_SMF.php extension? Lets compat it.
        if (!empty($GLOBALS['wgSMFLogin'])) {
            $this->compatAuthSMF();
        }

        // Administrator always get admin rights.
        if (!in_array(1, $GLOBALS['wgFSPAdminGroups']))
            $GLOBALS['wgFSPAdminGroups'][] = 1;

        if (!in_array(1, $GLOBALS['wgFSPInterfaceGroups']))
            $GLOBALS['wgFSPInterfaceGroups'][] = 1;

        if (is_readable($GLOBALS['wgFSPPath'] . '/Settings.php')) {
            require ($GLOBALS['wgFSPPath'] . '/Settings.php');
            if ($this->debug) {
                $this->logger->info('Loading Settings.php...');
            }
            // Globals declared in Settings.php gain local scope.
            $this->cookieName = $cookiename;
            $GLOBALS['wgFSPBoardURL'] = $boardurl; // Needs to be called from static functions.

            $this->decodeCookie();

            if ($this->userId && is_integer($this->userId)) {
                if ($this->debug) {
                    $this->logger->info('User detected, attempting to load database...');
                }

                $this->prefix = $db_prefix;

                if (empty($cookie_no_auth_secret) && !empty($auth_secret)) {
                    $this->authSecret = $auth_secret;
                }

                // TODO: make use of $db_type to support other databases.
                $this->databaseDriver = $db_type;

                $this->loaded = $this->FSDBConnect($db_server, $db_user, $db_passwd, $db_name);
            }
        }
        else {
            $this->logger->warning('Settings.php missing or not readable. Tried to load: ' . $GLOBALS['wgFSPPath'] . '/Settings.php');
        }
    }

    /**
     * Populates settings for the old Auth_SMF extension as needed.
     *
     * Don't overwrite more modern variables if set.
     */
    private function compatAuthSMF() {

        if ($this->debug) {
            $this->logger->info('Loading SMF_Auth compatability...');
        }

        if (!is_readable($GLOBALS['wgFSPPath'] . '/Settings.php')) {
            if (isset($GLOBALS['wgSMFPath']) && is_readable($GLOBALS['wgSMFPath'] . '/Settings.php')) {
                $GLOBALS['wgFSPPath'] = $GLOBALS['wgSMFPath'];
            }
            else {
                $GLOBALS['wgFSPPath'] = '../forum';
            }
        }

        if (empty($GLOBALS['wgFSPDenyGroups'])) {
            $GLOBALS['wgFSPDenyGroups'] = $GLOBALS['wgSMFDenyGroupID'];
        }

        if (empty($GLOBALS['wgFSPAllowGroups'])) {
            $GLOBALS['wgFSPAllowGroups'] = $GLOBALS['wgSMFGroupID'];
        }

        if (empty($GLOBALS['wgFSPAdminGroups'])) {
            $GLOBALS['wgFSPAdminGroups'] = $GLOBALS['wgSMFAdminGroupID'];
        }

        // By default they'll expect this.
        if (empty($GLOBALS['wgFSPInterfaceGroups'])) {
            $GLOBALS['wgFSPInterfaceGroups'] = $GLOBALS['wgSMFAdminGroupID'];
        }

        if (empty($GLOBALS['wgFSPSpecialGroups'])) {
            $GLOBALS['wgFSPSpecialGroups'] = $GLOBALS['wgSMFSpecialGroups'];
        }

        if (empty($GLOBALS['wgFSPNameStyle'])) {
            $GLOBALS['wgFSPNameStyle'] = 'smf';
        }

        // Enable the ban check unless explicitly disabled.
        if ($GLOBALS['wgFSPEnableBanCheck'] !== false) {
            $GLOBALS['wgFSPEnableBanCheck'] = true;
        }
    }

    /**
     * Database connection wrapper for PDO.
     *
     * @param string $db_server
     * @param string $db_user
     * @param string $db_passwd
     * @param string $db_name
     * @return bool
     */
    private function FSDBConnect($db_server, $db_user, $db_passwd, $db_name) {
        $dsn = '';

        switch ($this->databaseDriver) {
            case 'postgresql':
                $dsn = 'pgsql:host='. $db_server . ';dbname=' . $db_name;
                break;
            case 'sqlite': // I have no idea if this will ever get used. But hey.
                $dsn = 'sqlite:' . $db_name;
                if (substr($db_name, -3) != '.db')
                    $dsn .= '.db';
                break;
            case 'mysql':
            default: // Assume Mysql
                $dsn = 'mysql:host='. $db_server . ';dbname=' . $db_name;
        }

        try {
            $this->db = new PDO($dsn, $db_user, $db_passwd);
            return true;
        } catch (PDOException $e) {
            $this->FSDBError('PDO failed to connect to forum database:', $e);
            return false;
        }
    }

    /**
     * Database error wrapper
     *
     * @param string $error
     * @param PDOException $e
     */
    protected function FSDBError($error, PDOException $e) {
        $this->logger->warning($error);
        $this->logger->warning('[' . $this->databaseDriver . '|' . $e->getCode() . ']: ' . $e->getMessage());
    }

    /**
     * Run the query and if applicable display the mysql error.
     *
     * @param string $query
     * @return bool|PDOStatement
     */
    protected function FSDBQuery($query) {
        try {
            $request = $this->db->prepare($query);
            $request->execute();
        } catch (PDOException $e) {
            $this->FSDBError('Query failed: ' . $query, $e);
            return false;
        }
        return $request;
    }

    /**
     * Fetch the query with assoc.
     *
     * @param PDOStatement $request
     * @return bool|PDORow
     */
    public function FSDBFetchAssoc($request) {
        try {
            $row = $request->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->FSDBError('Error attempting to fetch row:', $e);
            return false;
        }
        return $row;
    }

    /**
     * Fetch the query.
     *
     * @param PDOStatement $request
     * @return bool|PDORow
     */
    public function FSDBFetchRow($request) {
        try {
            $row = $request->fetch(PDO::FETCH_NUM);
        } catch (PDOException $e) {
            $this->FSDBError('Error attempting to fetch row:', $e);
            return false;
        }
        return $row;
    }

    /**
     * Free the query.
     *
     * @param PDOStatement $request
     * @return bool
     */
    protected function FSDBFree($request) {
        try {
            $request->closeCursor();
            $request = null;
        } catch (PDOException $e) {
            $this->FSDBError('Error trying to free request:', $e);
            return false;
        }
        return true;
    }

    private function decodeCookie() {
        switch ($GLOBALS['wgFSPSoftware']) {
            case 'elk1.0':
            case 'elk1.1':
            case 'smf2.1':
                list($this->userId, $this->password) = json_decode($_COOKIE[$this->cookieName]);
                break;
            case 'smf2.0':
                list($this->userId, $this->password) = unserialize($_COOKIE[$this->cookieName]);
                break;
            default: return;
        }

        $this->userId = (int) $this->userId;
        $this->password = (string) $this->password;
    }

    /**
     * Called through MediaWiki.
     *
     * @param $special
     * @param $subPage
     *
     * Most previous handlers have either been depreciated or don't work with the session-based concept.
     *
     * SpecialPageBeforeExecute serves the same purpose.
     *
     * TODO: Apparently redirects are working with no further effort?
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

    /**
     * Sends the browser to the specified SMF/Elkarte page.
     *
     * @param string $action
     */
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
                    return $this->password === hash_hmac('sha1', sha1($this->userForum['passwd'] . $this->userForum['password_salt']), $this->authSecret);
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

    /**
     * This function is called by MediaWiki itself
     *
     * @param WebRequest $request
     * @return SessionInfo|null
     */
    public function provideSessionInfo(WebRequest $request) {
        if (!$this->loaded) {
            return null;
        }

        // Apparently this somehow kills itself between the constructor and getting called here.
        $this->logger = LoggerFactory::getInstance('ForumSessionProvider');

        if ($this->debug) {
            $this->logger->info('Database loaded, attempting to load forum member...');
        }

        $result = $this->FSDBQuery("
                SELECT member_name, email_address, real_name, passwd, password_salt, id_group, additional_groups
                FROM {$this->prefix}members
                WHERE id_member = '{$this->userId}' AND is_activated = 1
                LIMIT 1
            ");

        $this->userForum = $this->FSDBFetchAssoc($result);
        $this->FSDBFree($result);

        if (empty($this->userForum)) {
            $this->logger->warning('Member id not found in forum database: ' . $this->userId);
            return null;
        }
        else if ($this->debug) {
            $this->logger->info('Forum member found, verifying cookie...');
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
                        $this->logger->warning('Member failed to validate domain pattern: ' . $this->userId);
                        return null;
                    }
                    break;
                default:
                    // Just kick them if they have an unusable username.
                    if (preg_match('`[#<>[\]|{}@:]+`', $this->userName)) {
                        $this->logger->warning('Member with invalid name: ' . $this->userId);
                        return null;
                    }
            }

        }
        else {
            $this->logger->warning('Member ID ' . $this->userId . ' failed to validate. Remote IP:' . $_SERVER['REMOTE_ADDR']);
            return null;
        }

        if ($this->debug) {
            $this->logger->info('Member found and verified, verifying access...');
        }

        if (strlen($this->userForum['additional_groups'])) {
            $this->userGroups = explode(',', $this->userForum['additional_groups']);
        }
        $this->userGroups[] = $this->userForum['id_group'];

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

        if ((!array_intersect($GLOBALS['wgFSPAllowGroups'], $this->userGroups) ||
                array_intersect($GLOBALS['wgFSPDenyGroups'], $this->userGroups) ||
                $this->isBanned()) &&
                !array_intersect($GLOBALS['wgFSPAdminGroups'], $this->userGroups) &&
                !array_intersect($GLOBALS['wgFSPSuperGroups'], $this->userGroups)) {
            $this->logger->warning('Member denied access: ' . $this->userId);
            return null;
        }
        else if ($this->debug) {
            $this->logger->info('Access granted!');
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

        return new SessionInfo(SessionInfo::MAX_PRIORITY, [
            'provider' => $this,
            'id' => $id,
            'userInfo' => $this->userInfo,
            'persisted' => $persisted,
            'forceUse' => $forceUse,
        ]);
    }

    private function updateWikiUser() {
        $this->userWiki->setEmail($this->userForum['email_address']);
        $this->userWiki->setRealName($this->userForum['real_name']);

        if ($this->userWiki->getOption('forum_member_id', 0) === 0) {
            $this->userWiki->setOption('forum_member_id', $this->userId);
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
            if (array_intersect($fs_group_ids, $this->userGroups) && !in_array($wiki_group_name, $this->userWiki->getEffectiveGroups()))
                $this->userWiki->addGroup($wiki_group_name);
            // They are not in the Forum group, but in the wiki group
            elseif (!array_intersect($fs_group_ids, $this->userGroups) && in_array($wiki_group_name, $this->userWiki->getEffectiveGroups()))
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

    /**
     * This is broken out because I suspect banning code is going to evolve a bit differently between forks.
     *
     * @return bool|PDORow
     */
    private function isBannedSMF() {
        $result = $this->FSDBQuery('
            SELECT id_ban
            FROM ' . $this->prefix . 'ban_items AS i
            LEFT JOIN ' . $this->prefix . 'ban_groups AS g
                ON (i.id_ban_group = g.id_ban_group)
            WHERE i.id_member = ' . ( (int) $this->userId) . '
                AND (g.cannot_post = 1 OR g.cannot_login = 1)');

        $banned = $this->FSDBFetchRow($result);
        $this->FSDBFree($result);

        if (!empty($banned)) {
            $banned = true;
        }
        else {
            $banned = false;
        }

        $this->userWiki->setOption('forum_last_update_ban', time());
        $this->userWiki->setOption('forum_is_banned', $banned);
        $this->userWiki->saveSettings();

        return $banned;
    }
}