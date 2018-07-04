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
    public $task = 'login';

    private $rc;
    private $ldap;

    function init()
    {
        $this->rc = rcmail::get_instance();

        $this->add_hook('user_create', array($this, 'lookup_user_name'));
        $this->add_hook('login_after', array($this, 'login_after'));
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
        $user_fields = $this->rc->config->get('esco_user_identity_complete_user_fields');
        // si cette liste est définie on récupère les attributs du ldap pour les ajouter à la définiton du user
        if (!empty($user_fields)) {
            if ($this->init_ldap('')) {
                $results = $this->ldap->search('*', $this->rc->user->data['username'], 1);
                if (count($results->records) == 1) {
                    // on ajoute les attributs utilisateur
                    foreach ($user_fields as $attr) {
                        $user_attr = strtolower($attr);
                        $val = $results->records[0]['_raw_attrib'][$user_attr];
                        if (!empty($val)) {
                            $this->rc->user->data[$user_attr] = $val;
                        }
                    }
                    $this->rc->user->data['esco_user_inited'] = 'DONE';
                }
            }
        }

        $_SESSION['user_data'] = $this->rc->user->data;
        $this->ldap->user = $this->rc->user;

        return $args;
    }

    private function init_ldap($host)
    {
        if ($this->ldap) {
            return $this->ldap->ready;
        }

        $this->load_config();

        $addressbook = $this->rc->config->get('esco_user_identity_addressbook');
        $ldap_config = (array)$this->rc->config->get('ldap_public');
        $match = $this->rc->config->get('esco_user_identity_match');

        if (empty($addressbook) || empty($match) || empty($ldap_config[$addressbook])) {
            return false;
        }

        $this->ldap = new esco_user_identity_ldap_backend(
            $ldap_config[$addressbook],
            $this->rc->config->get('ldap_debug'),
            $this->rc->config->mail_domain($host),
            $match);

        return $this->ldap->ready;
    }
}

class esco_user_identity_ldap_backend extends rcube_ldap{

    private $str_dyn='%dynamic';

    function __construct($p, $debug, $mail_domain, $search)
    {
        parent::__construct($p, $debug, $mail_domain);
        $this->prop['search_fields'] = (array)$search;
    }

    function set_search_set($filter)
    {
        parent::set_search_set($this->apply_dyn_filter($filter));

    }

    private function apply_dyn_filter($filter)
    {
        $user_data = $_SESSION['user_data'];
        if (strlen(strstr($filter, $this->str_dyn)) > 0) {
            $dynamic_user_fields = $this->prop['dynamic_user_fields'];
            $dynamic_filter = '';
            $required_respected = true;
            if (!empty($dynamic_user_fields)) {
                $fields = array();
                if (is_array($dynamic_user_fields)) {
                    $fields = $dynamic_user_fields;
                } else {
                    $fields = array($dynamic_user_fields);
                }
                foreach ($fields as $user_attr) {
                    $attr = strtolower($user_attr);
                    if (!empty($user_data[$attr])) {
                        $dynamic_filter .= "(|";
                        foreach ($user_data[$attr] as $val) {
                            if (!empty($val)) {
                                $dynamic_filter .= "(|";
                                foreach ($fields as $user2_attr) {
                                    $attr2 = strtolower($user2_attr);
                                    $dynamic_filter .= "(" . $attr2 . "=" . $val . ")";
                                }
                                $dynamic_filter .= ")";
                            }
                        }
                        $dynamic_filter .= ")";
                    } else if (in_array(strtolower($user_attr), $this->prop['required_fields'])) {
                        $required_respected = false;
                    }
                }
            }
            if ($required_respected || (is_array($user_data) && !array_key_exists('new_user_inited', $user_data))) {
                $new_filter = str_replace($this->str_dyn, $dynamic_filter, $filter);
                $this->dyn_filter = $dynamic_filter;
                return $new_filter;
            }
        }
        return $filter;
    }
}
