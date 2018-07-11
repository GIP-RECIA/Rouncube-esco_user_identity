<?php

/**
 * New user identity
 *
 * Populates a new user's default identity from LDAP on their first visit.
 *
 * This plugin requires that a working public_ldap directory be configured.
 *
 * @author Kris Steinhoff
 * @license GNU GPLv3+
 */
class esco_user_identity extends rcube_plugin
{
//    public $task = 'login';

    private $ldap;

    function init()
    {
        $this->add_hook('user_create', array($this, 'lookup_user_name'));
        $this->add_hook('login_after', array($this, 'login_after'));
        $this->add_hook('refresh_user', array($this, 'refresh_user'));
    }

    function lookup_user_name($args)
    {
        if ($this->init_ldap($args['host'])) {
            $results = $this->ldap->search('*', $args['user'], true);

            if (count($results->records) == 1) {
                $user_name = is_array($results->records[0]['name']) ? $results->records[0]['name'][0] : $results->records[0]['name'];
                $user_email = is_array($results->records[0]['email']) ? $results->records[0]['email'][0] : $results->records[0]['email'];

                $args['user_name'] = $user_name;
                $args['email_list'] = array();

                if (!$args['user_email'] && strpos($user_email, '@')) {
                    $args['user_email'] = rcube_utils::idn_to_ascii($user_email);
                }
                $rcmail = rcmail::get_instance();

                if (($alias_col = $rcmail->config->get('esco_user_identity_alias')) && $results->records[0][$alias_col]) {
                    $args['alias'] = is_array($results->records[0][$alias_col]) ? $results->records[0][$alias_col][0] : $results->records[0][$alias_col];
                }

                foreach (array_keys($results[0]) as $key) {
                    if (!preg_match('/^email($|:)/', $key)) {
                        continue;
                    }

                    foreach ((array)$results->records[0][$key] as $alias) {
                        if (strpos($alias, '@')) {
                            $args['email_list'][] = rcube_utils::idn_to_ascii($alias);
                        }
                    }
                }

            }
        }

        return $args;
    }

    function login_after($args)
    {
        $this->load_config();

        // on récupère la liste des attributs utilisateurs à récupérer du ldap
        $user_fields = rcmail::get_instance()->config->get('esco_user_identity_complete_user_fields');
        // si cette liste est définie on récupère les attributs du ldap pour les ajouter à la définiton du user
        if (!empty($user_fields)) {
            if ($this->init_ldap('')) {
                $results = $this->ldap->search('*', rcmail::get_instance()->user->data['username'], 1);
                if (count($results->records) == 1) {
                    // on ajoute les attributs utilisateur
                    foreach ($user_fields as $attr) {
                        $user_attr = strtolower($attr);
                        $val = $results->records[0]['_raw_attrib'][$user_attr];
                        if (!empty($val)) {
                            rcmail::get_instance()->user->data[$user_attr] = $val;
                        }
                    }
                    rcmail::get_instance()->user->data['esco_user_inited'] = 'DONE';
                }
            }
        }

        $_SESSION['user_data'] = rcmail::get_instance()->user->data;
        $this->ldap->user = rcmail::get_instance()->user;

        return $args;
    }

    function refresh_user($args){
        return $this->login_after($args);
    }

    private function init_ldap($host)
    {
        if ($this->ldap) {
            return $this->ldap->ready;
        }

        $this->load_config();

        $addressbook = rcmail::get_instance()->config->get('esco_user_identity_addressbook');
        $ldap_config = (array)rcmail::get_instance()->config->get('esco_ldap');
        $match = rcmail::get_instance()->config->get('esco_user_identity_match');

        if (empty($addressbook) || empty($match) || empty($ldap_config[$addressbook])) {
            return false;
        }

        $this->ldap = new esco_user_identity_ldap_backend(
            $ldap_config[$addressbook],
            rcmail::get_instance()->config->get('ldap_debug'),
            rcmail::get_instance()->config->mail_domain($host),
            $match);

        return $this->ldap->ready;
    }
}

class esco_user_identity_ldap_backend extends rcube_ldap{

    function __construct($p, $debug, $mail_domain, $search)
    {
        parent::__construct($p, $debug, $mail_domain);
        $this->prop['search_fields'] = (array)$search;
    }

}
