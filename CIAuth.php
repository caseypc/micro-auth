<?php
/**
* CIAuth
* 
* CIAuth is one simple file codeigniter library for user management and authentication.
* Violating SRP hahah ..
* 
* @package Core
* @author Gemblue
* 
*/

class CIAuth
{
    // Init
    private $ci;
    
    // Table setting
    public $user = 'users';
    public $user_extra = 'user_extra';
    public $user_role = 'user_role';
    
    // Session name setting
    public $global_logged_in_name = 'logged_in';
    
    public function __construct()
    {
        $this->ci =& get_instance();
    }
    
    /*
    Param : access_code / password + venue slug
    Purpose : to login just by access code
    */
    public function verify_access_code($param)
    {
        $user = $this->get_detail(array(
            'get' => $this->user . '.id as user_id',
            'condition' => array(
                'venue_slug' => $param['venue_slug'],
                'password' => md5($param['password'])
                )
            ));
            
            if (empty($user) || $user == false)
            {
                return false;
            }
            else
            {
                // Fill session.
                $this->ci->session->set_userdata(array(
                    $this->global_logged_in_name => true,
                    'user_id' => $user[0]->user_id
                ));
                
                return true;
            }
        }
        
        /*
        Param : array(username, password)
        Purpose : to login check and auth
        */
        public function login($param)
        {
            $user = $this->get_detail(array(
                'get' => $this->user . '.id as user_id, name, role',
                'condition' => array(
                    'username' => $param['username'],
                    'venue_slug' => $param['venue_slug'],
                    'password' => md5($param['password'])
                    )
                ));
                
                if (empty($user) || $user == false)
                {
                    return false;
                }
                else
                {
                    // Fill session.
                    $this->ci->session->set_userdata(array(
                        $this->global_logged_in_name => true,
                        'role_' . $user[0]->role => true,
                        'role_name' => $user[0]->role,
                        'username' => $param['username'],
                        'user_id' => $user[0]->user_id,
                        'name' => $user[0]->name
                    ));
                    
                    // Update last login
                    $this->ci->db->update($this->user, array('last_login' => date('y-m-d H:i:s')), array('id' => $user[0]->user_id));
                    
                    return true;
                }
            }
            
            /*
            Param : session_name
            Purpose : to get current session value
            */
            public function current($session_name)
            {
                return $this->ci->session->userdata($session_name);
            }
            
            /*
            Param : -
            Purpose : to check is user logged in with some role, or no.
            */
            public function logged_in($role = null)
            {
                if ($role != null)
                {
                    return $this->ci->session->userdata('role_' . $role);
                }
                
                return $this->ci->session->userdata($this->global_logged_in_name);
            }
            
            /*
            Param : -
            Purpose : to logout the CIAuth session.
            */
            public function logout()
            {
                $this->ci->session->sess_destroy();
                return true;
            }
            
            /*
            Param : user id, extra session
            Purpose : pemaksaan login, langsung mengisi session berdasarkan id tertentu.
            untuk kebutuhan login pihak ketiga dan lainnnya. Bisa menambahkan session
            yang dirasa perlu juga.
            */
            public function force_login($user_id, $extra_session = null)
            {
                if ($extra_session != null)
                {
                    $this->ci->session->set_userdata($extra_session);
                }
                
                // Force login with user id
                $user = $this->get_detail(array(
                    'get' => $this->user . '.id as user_id, username, name, role',
                    'condition' => array(
                        $this->user . '.id' => $user_id
                        )
                    ));
                    
                    if (empty($user) || $user == false)
                    {
                        return false;
                    }
                    else
                    {
                        // Fill session.
                        $this->ci->session->set_userdata(array(
                            $this->global_logged_in_name => true,
                            'role_' . $user[0]->role => true,
                            'role_name' => $user[0]->role,
                            'username' => $user[0]->username,
                            'user_id' => $user[0]->user_id,
                            'name' => $user[0]->name
                        ));
                        
                        // Update last login
                        $this->ci->db->update($this->user, array('last_login' => date('y-m-d H:i:s')), array('id' => $user[0]->user_id));
                        
                        return true;
                    }
                }
                
                /*
                Param : array('role_name')
                Purpose : to protect controller/function with role, only allow several role to access.
                */
                public function verify($param)
                {
                    // Check session one by one.
                    foreach ($param as $role_name)
                    {
                        if ($this->ci->session->userdata('role_' . $role_name) == true)
                        return true;
                    }
                    
                    return false;
                }
                
                /*
                Param : array (email, name, username, active)
                Purpose : register the user.
                */
                public function register($param, $force = false)
                {
                    $by_machine = array(
                        'created_at' => date('Y-m-d H:i:s'),
                        'ip_address' => $_SERVER['REMOTE_ADDR']
                    );
                    
                    if ($force == false)
                    {
                        // Email check.
                        $email_check = $this->get_single_field(array(
                            'get' => 'id',
                            'condition' => array('role_id !=' => 5, 'email' => $param['email'], 'venue_slug' => $param['venue_slug'])
                        ));
                        
                        if ($email_check != false)
                        {
                            return array('status' => false, 'message' => 'email is exist');
                        }
                        
                        // Username check.
                        $username_check = $this->get_single_field(array(
                            'get' => 'id',
                            'condition' => array('role_id !=' => 5, 'username' => $param['username'], 'venue_slug' => $param['venue_slug'])
                        ));
                        
                        if ($username_check != false)
                        {
                            return array('status' => false, 'message' => 'username is exist');
                        }
                    }
                    
                    if ($this->ci->db->insert($this->user, array_merge($param, $by_machine)))
                    {
                        return array('status' => true, 'message' => 'sucessfully executed', 'insert_id' => $this->ci->db->insert_id());
                    }
                }
                
                /*
                Param : user_id, name, email, etc
                Purpose : update user main table by user id
                */
                public function update($param, $user_id)
                {
                    $by_machine = array(
                        'updated_at' => date('Y-m-d H:i:s')
                    );
                    
                    if ($this->ci->db->update($this->user, array_merge($param, $by_machine), array('id' => $user_id)))
                    {
                        return true;
                    }
                }
                
                /*
                Param : array('socmed_name', 'socmed_id', 'second_address', '...')
                Purpose : update user extra data, after main table inserted
                */
                public function update_extra($param)
                {
                    // Check the existing user first.
                    $user_exist = $this->get_single_field(array(
                        'get' => 'user_id',
                        'condition' => array('user_id' => $param['user_id'])
                    ), $this->user_extra);
                    
                    if ($user_exist == false)
                    {
                        // If not exist, fresh insert
                        if ($this->ci->db->insert($this->user_extra, $param))
                        {
                            return true;
                        }
                    }
                    else
                    {
                        if ($this->ci->db->update($this->user_extra, $param, array('user_id' => $param['user_id'])))
                        {
                            return true;
                        }
                    }
                }
                
                /*
                Param : array(field_to_get, condition)
                Purpose : to get single field value by condition
                */
                public function get_single_field($param, $table = null)
                {
                    $this->ci->db->select($param['get'] . ' AS item');
                    
                    // Prepare Condition
                    if (!empty($param['condition']))
                    {
                        foreach ($param['condition'] as $where => $value)
                        {
                            $this->ci->db->where($where, $value);
                        }
                    }
                    
                    // Prepare table to operate, default or defined
                    if ($table != null)
                    $result = $this->ci->db->get($table)->result(); // Defined
                    else
                    $result = $this->ci->db->get($this->user)->result(); // Default
                    
                    if (!empty($result))
                    {
                        return $result[0]->item;
                    }
                    else
                    {
                        return false;
                    }
                }
                
                /*
                Param : array('get, array(condition)').
                Purpose : to get more then one field value by any condition.
                */
                public function get_detail($param = null)
                {
                    // Select
                    $this->ci->db->select($param['get']);
                    $this->ci->db->join($this->user_extra, $this->user_extra . '.user_id = '. $this->user . '.id');
                    $this->ci->db->join($this->user_role, $this->user_role . '.id = '. $this->user . '.role_id');
                    
                    // Prepare Condition
                    if (!empty($param['condition']))
                    {
                        foreach ($param['condition'] as $where => $value)
                        {
                            $this->ci->db->where($where, $value);
                        }
                    }
                    
                    return $this->ci->db->get($this->user)->result();
                }
                
                /*
                Param : array('get, array(condition), paging, order').
                Purpose : to get loop row/record by some field with paging.
                Sample : get 20 row where field name like "The".
                */
                public function get_loop($param = null)
                {
                    // Select
                    $this->ci->db->select($param['get']);
                    $this->ci->db->join($this->user_role, $this->user_role. '.id=' . $this->user . '.role_id');
                    
                    // Prepare Condition
                    if (!empty($param['condition']))
                    {
                        foreach ($param['condition'] as $where => $value)
                        {
                            $this->ci->db->where($where, $value);
                        }
                    }
                    
                    // Prepare Condition Like
                    if (!empty($param['condition_like']))
                    {
                        foreach ($param['condition_like'] as $where => $value)
                        {
                            $this->ci->db->like($where, $value);
                        }
                    }
                    
                    // Prepare Condition Like
                    if (!empty($param['condition_or']))
                    {
                        foreach ($param['condition_or'] as $where => $value)
                        {
                            $this->ci->db->or_where($where, $value);
                        }
                    }
                    
                    // Prepare paging
                    if (!empty($param['paging']))
                    {
                        $paging = explode('/', $param['paging']);
                        $this->ci->db->limit($paging[0], $paging[1]);
                    }
                    
                    // Prepare order
                    if (!empty($param['order']))
                    {
                        $order = explode(',', $param['order']);
                        $this->ci->db->order_by($order[0], $order[1]);
                    }
                    
                    return $this->ci->db->get($this->user)->result();
                }
                
                /*
                Param : -
                Purpose : to get total by some condition or not.
                Sample : get total record where name is "Tom"
                */
                public function get_total($condition = null, $mode = null)
                {
                    // Select
                    $this->ci->db->select('id');
                    
                    if ($mode == 'like')
                    {
                        // Prepare Condition
                        if (!empty($condition))
                        {
                            foreach ($condition as $where => $value)
                            {
                                $this->ci->db->like($where, $value);
                            }
                        }
                    }
                    else
                    {
                        // Prepare Condition
                        if (!empty($condition))
                        {
                            foreach ($condition as $where => $value)
                            {
                                $this->ci->db->where($where, $value);
                            }
                        }
                    }
                    
                    return $this->ci->db->get($this->user)->num_rows();
                }
                
                /*
                Param : validation number
                Purpose : check validation number sent by sms.
                Sample : -
                */
                public function is_valid($number)
                {
                    $valid = $this->get_single_field(array(
                        'get' => 'user_id',
                        'condition' => array('validation' => $number)
                    ), $this->user_extra);
                    
                    if (!empty($valid))
                    return $valid;
                    else
                    return false;
                }
                
                /*
                Custom
                */
                
                // Get total register per day, by venue slug
                function get_register_per_date($param = null)
                {
                    $sql = "SELECT COUNT( id ) AS total_register, DATE( created_at ) created_at FROM `users` WHERE venue_slug = '$param[venue_slug]' AND (created_at BETWEEN  '$param[date_start]' AND  '$param[date_end]') group by CAST(created_at AS DATE)";
                    return $this->ci->db->query($sql)->result();
                }
                
                // Get users by role.
                function get_users($role_id, $venue = null)
                {
                    $this->ci->db->select('users.id, user_role.role, users.name, users.username, users.email, users.venue_slug, users.last_login, users.created_at');
                    $this->ci->db->join($this->user_role, $this->user_role. '.id=' . $this->user . '.role_id');
                    
                    $i = 0;
                    
                    foreach($role_id as $id)
                    {
                        if ($i == 0)
                        {
                            // Where
                            $this->ci->db->where($this->user . '.role_id', $id);
                            
                            if (!empty($venue))
                            {
                                $this->ci->db->where($this->user . '.venue_slug', $venue);
                            }
                        }
                        else
                        {
                            // Or Where
                            $this->ci->db->or_where($this->user . '.role_id', $id);
                            
                            if (!empty($venue))
                            {
                                $this->ci->db->where($this->user . '.venue_slug', $venue);
                            }
                        }
                        
                        $i++;
                    }
                    
                    return $this->ci->db->get($this->user)->result();
                }
            }
            ?>
            