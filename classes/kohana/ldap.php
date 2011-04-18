<?php defined('SYSPATH') or die('No direct script access.');

/**
 * Kohana Ldap module/model
 * @author t0meck
 */
class Kohana_Ldap {
	protected $config = array();
	protected $connection = NULL;
	
	public static function factory(array $config = array())	{
		return new Ldap($config);
	}
	
	public function __construct(array $config = array())	{
		// Nadpisanie wartosci domyslnych systemu przez ustawienia aplikacji
		$this->config = $this->config_group() + $this->config;
	}
	
	/**
	 * Wyciaga ustawienia modulu z pliku konfiguracyjnego rekurencyjnie
	 * (pliki mogą się odwoływać wzajemnie do siebie)
	 * 
	 * @param string - nazwa grupy konfiguracji modulu; 'default' gdy nic nie podano
	 * @return Array - tablica ustawien modulu
	 */
	public function config_group($group = 'default')	{
		
		// Wczytanie pliku konfiguracyjnego modulu
		$config_file		= Kohana::config('ldap');
		
		// Inicjalizacja tablicy ustawien
		$config				= array('group'=>(string) $group);
		
		// Rekurencyjne ladowanie wybranych grup ustawien
		while(isset($config['group']) && isset($config_file->$config['group']))	{
			// Tymczasowo przetrzymaj nazwe ustawien
			$group = $config['group'];
			unset($config['group']);
			
			// Dopisanie wczytanych danych do aktualnej konfiguracji
			$config += $config_file->$group;
		}
		
		// Pozbycie sie mozliwych zbednych nazw grup ustawien
		unset($config['group']);
		
		// Zwrocenie polaczonych obu tablic z ustawieniami
		return $config;
	}
	
	/**
	 * Nawiazuje polaczenie z serwerem LDAP i ustawia parametry polaczenia
	 * aby mozna bylo wykonywac przeszukiwanie serwera LDAP
	 * 
	 * @return boolean
	 */
	protected function connect()	{
		if ($this->connection == NULL)
			$this->connection = @ldap_connect($this->config['ldap_server_address'], $this->config['ldap_server_port']);
			
		if($this->connection){
			@ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, $this->config['ldap_opt_protocol_version']);
			@ldap_set_option($this->connection, LDAP_OPT_REFERRALS, $this->config['ldap_opt_referrals']);
			return TRUE;
		}
		return FALSE;
	}
	
	/**
	 * Zamyka polaczenie z serwerem LDAP
	 * 
	 * @return boolean
	 */
	protected function disconnect()	{
		if($this->connection)
			return @ldap_close($this->connection);
		return FALSE;
	}
	
	/**
	 * Loguje sie do serwera LDAP przy pomocy loginu i hasla z pliku konfiguracyjnego
	 * Ta metoda jest uzywana przy przeszukiwaniu LDAP'a
	 * 
	 * @return boolean
	 */
	protected function bind()	{
		if ($this->connection)	{
			return @ldap_bind($this->connection, $this->config['ldap_login'].'@'.$this->config['domain'], $this->config['ldap_password']);
		}
		return FALSE;
	}
	
	/**
	 * Sprawdza czy podany login i haslo przechodza autoryzacje
	 * 
	 * @param string $login
	 * @param string $password
	 * @return boolean
	 */
	public function login($login, $password)	{
		if($this->connect())	{
			if (strlen($login) > 0 && strlen($password) > 0)	{
				return @ldap_bind($this->connection, $login.'@'.$this->config['domain'], $password);
			}
			$this->disconnect();
		}
		return FALSE;
	}
	
	/**
	 * Sprawdza czy na serwerze LDAP istnieje uzytkownik o podanym loginie
	 * i jesli tak to zwraca tablice z wybranymi w pliku konfiguracyjnym atrybutami
	 * jesli nie to zwraca NULL.
	 * Jest to funkcja wykorzystywana takze wewnetrznie.
	 * 
	 * @param string $login - login uzytkownika ktorego dane maja zostac zwrocone
	 * @return Mixed
	 */
	public function find($login)	{
		if (strlen($login) > 0)	{
			if($this->connect()) {
				if ($this->bind()) {
					$filter = 'cn='.$login;
					$search_result = @ldap_search($this->connection, $this->config['base_dn'], $filter, $this->config['attributes']);
					$result = @ldap_get_entries($this->connection, $search_result);
					if (isset($result)){
						$attributes_result = array();
						foreach($this->config['attributes'] as $attribute)	{
							$attributes_result[$attribute] = $result[0][$attribute][0];
						}
						$output = array_merge(array('login' => $login), $attributes_result);
					}else{
						$output = NULL;
					}
					$this->disconnect();
					return $output;
				}
				$this->disconnect();
			}			
		}
		return NULL;
	}
	
	/**
	 * Wyszukuje w serwerze LDAP uzytkownikow spelniajacych kryteria
	 * i zwraca tablice uzytkownikow z ich atrybutami ustawionymi w pliku konfiguracyjnym.
	 * Wyszukiwanie nastepuje sprawdzajac pole 'displayName'.
	 * 
	 * @param string $first - imie lub nazwisko
	 * @param string $last  - nazwisko (opcjonalnie)
	 * @return Array
	 */
	public function search($first, $last = NULL){
		if(strlen($first) > 0){
			$search_string = '';
			$search_string .= '*'.$first.'*';
			if ($last != NULL) {
				$search_string .= ' *'.$last.'*';
			}
			if ($this->connect()){
				if ($this->bind()){
					$filter = '(objectClass=user)';
					$filter .= '(displayName='.$search_string.')';
					$filter = '(&'.$filter.')';
					
					// ponizsza linia powoduje wyszukanie w LDAP-ie tylko tych atrybutow ktore sa ustawione w pliku konfiguracyjnym
					$search_result = @ldap_search($this->connection, $this->config['base_dn'], $filter, $this->config['attributes']);
					
					// ponizsza linia powoduje wyszukanie w LDAP-ie wszystkich atrybutow
					// $search_result = @ldap_search($this->connection, $this->config['base_dn'], $filter);
					
					$result = @ldap_get_entries($this->connection, $search_result);
					if (isset($result)){
						$output = array();
						for($i=0;$i<$result['count'];$i++){
							$user = array();
							$row = $result[$i];
							for($j=0;$j<$row['count'];$j++){
								$label = $row[$j];
								$field = $row[$label][0];
								$user[$label] = $field;
							}
							$output[] = $user;
						}
						return $output;
					}
				}
			}
		}
		
		// Zwracamy NULL gdy wszystko inne zawiedzie
		return NULL;
	}
}

?>