class PifiController < ApplicationController
  def hello

    begin
      hello = parse_post_json()
    rescue StandardError => e
      send_response_error(e.message)
      return
    end

    if (hello.has_key? "mac")
      mac = hello["mac"]
    else
      send_response_error("mac key not found")
      return
    end

    mac = Mac.clean_mac(mac)

    ap = AccessPoint.find_by(mac: mac)

    # I think aba's code registers these as "raspberrypi". rename to Piglet if named "raspberry pi"
    if !ap.nil? && ap.name == "raspberrypi"
       last_four = mac.gsub(':', '')[-4..-1]
      ap.name = "Piglet AP (#{last_four})"
      ap.save
    end

    if ap.nil? # New AP
      ap = AccessPoint.find_or_initialize_by(mac: mac)

      infdev = ap.infrastructure_device ||= WlanDevice.find_by(device: 'piglet')
      unless infdev
        send_response_error('invalid WLAN controller configuration')
        return
      end

      last_four = mac.gsub(':', '')[-4..-1]
      ap.name          ||= "Piglet AP (#{last_four})"
      ap.save
    end

    radios = AccessPointRadio.where(:access_point_id => ap.id).order("wlan_if asc")
    note = [ ]
    radios.each do | radio|
      note << "radio #{radio.wlan_if} mac: #{radio.mac}"
    end

    # set the AP IP address to the remote IP address calling hello
    ap.ip = request.remote_ip

    if ap_info = hello['ap_info']
      ap.serial_number = ap_info["serial"] || ap.serial_number
      ap.model = ap_info["model"] || ap.model
      ap.version = ap_info["version"] || ap.version

      # grab detailed information on each wlan physical interface
      if wlans = hello["ap_info"]["wlans"]

        curr_radio_mac_list = [ ]

        wlans.each do |wlan|
          radio_mac = wlan["mac"]
          curr_radio_mac_list << radio_mac

          # see if radio exists with curent AP
          radio = AccessPointRadio.find_by(access_point_id: ap.id, mac: radio_mac)
          if (radio.nil?)
            # see if radio is associated with another AP. If so, delete it.
            radio = AccessPointRadio.find_by(mac: radio_mac)
            if (!radio.nil?)
              radio.destroy
            end
            radio = AccessPointRadio.find_or_initialize_by(access_point_id: ap.id, mac: radio_mac)
          end

          radio.phy_if = wlan["phy"]
          radio.wlan_if = wlan["wlan"]

          # rattle through all bands to get associated channels.
          channel_list = [ ]
          wlan.keys.grep(/^band/).each do |band|
            channel_list += wlan[band]["channels"]
          end

          #create unique list,sort accordingly and convert into integers.
          channel_list = channel_list.map(&:to_i).uniq.sort

          # Create comma separated list of all available channels
          radio.avail_channels = channel_list.join(",")

          # save all data passed as JSON to debug field
          radio.debug_data = wlans.to_json

          radio.save
        end
      end

      # Radio may be off temporarily and have a radio profile associated with it
      # delete any radios associated with AP that aren't in use.
      radios = AccessPointRadio.where(access_point_id: ap.id)
      radios.each do |radio|
        next if curr_radio_mac_list.include? radio.mac
        radio.destroy
      end
    end

    #Get infrastructure_device_id associated with AP's profile
    infrastructure_device_id = nil
    profiles = ap.effective_profiles();
    profiles.each do |profile|
        next if (profile == nil)
        infrastructure_device_id = profile.infrastructure_device_id;
        break # only get first? can there be multiple?
    end

    # Build list of WLAN's associated with the AP's effective Profile
    wlan_list = [ ]
    if (infrastructure_device_id != nil)
      Wlan.all.each do |wlan|
        next if (wlan.infrastructure_device_id != infrastructure_device_id)
        wlan_list << wlan
      end
    end

    # TODO: maybe get the csr or public key from the initial hello?
    ap.last_seen_at  = Time.now
    last_four = mac.gsub(':', '')[-4..-1]
    ap.name          ||= "Piglet (#{last_four})"

    # Save AP into table
    if ap.save
      if (ap.approved == true)
        hello_response = {
          status:       "approved",
          poll_timer:   5, #hard code for now, 30 seconds
          cert_url:     url_for(action: :request_cert),
        }
        send_response(hello_response, "Device Appoved")
        ap.pifi_error = nil
        ap.save
        return
      else
         hello_response = {
          status:       "registered",
          poll_timer:   30, #hard code for now, 30 seconds
        }
        send_response(hello_response, "Device Registered, pending approval")
        ap.pifi_error = "Device Registered, pending approval"
        ap.save
        return
      end
    else
      send_response_error("Unable to save AP record")
      return
    end

  end

  def register_client

    #Required Field - AP Mac address
    ap_mac = params[:ap_mac]
    if (ap_mac == nil)
      send_response_error("AP MAC not specified")
      return
    end

    #Required Field - Client MAC Address
    mac = params[:mac]
    if (mac == nil)
      send_response_error("Client MAC not specified")
      return
    end

    #Required Field - SSID
    ssid = params[:ssid]
    if (ssid == nil)
      send_response_error("SSID not specified")
      return
    end

    # clean up MAC Addresses to proper format
    ap_mac = Mac.clean_mac(ap_mac)
    mac = Mac.clean_mac(mac)

    client_hash = {
      'ap_mac' => ap_mac,
      'mac' => mac,
      'ssid' => ssid
    }

    #optional parameters to potentially look for.
    optional_params = %w(
      bytes_from_client
      bytes_to_client
      channel
      ip
      rssi
      snr
      rx_link_speed
      tx_link_speed
    )

    #if optional parameter exists, add it to client hash.
    optional_params.each { | param |
      if params[param] != nil
        client_hash[param] = params[param]
      end
    }

    # get AP associated
    ap = AccessPoint.find_by(mac: ap_mac)
    unless ap
      send_response_error("No access point with mac #{ap_mac} exists within rxg")
      return
    end

    wireless_clients = ap.try(:wireless_clients)

    #Load existing list of connected clients
    cached_clients = ap.connected_clients.includes(:switch_port => [:switch_port_profile, :infrastructure_link]).to_a

    # find index to existing client based on mac, and if new create new connected client instance.
    if index = cached_clients.find_index { |c| c.mac == client_hash['mac'] && c.vlan_tag == client_hash['vlan_tag'] }
      connected_client = cached_clients.delete_at(index)
    else
      #if new client
      connected_client = wireless_clients.new(mac: client_hash['mac'])
    end

    #find wlan based on passed SSID
    wlan = nil
    wlan_list = Wlan.all
    # a vsz may have wlans with the same name in different zones
    if client_hash['ssid']
      wlan = wlan_list.find { |w| w.access_point_zone_id == client_hash['access_point_zone_id'] && w.ssid == client_hash['ssid']}
    end

    if wlan == nil
      send_response_error("wlan with SSID '" + ssid + "' does not exist in rxg database for AP mac.")
      return
    end

    connected_client.wlan_id = wlan.try(:id)

    # take all fields in passed client_hash hash and merge into connected_client hash.
    client_hash.each do |k,v|
      next if k == 'id' # dont overwrite internal ID
      if connected_client.respond_to?("#{k}=")
        connected_client.send("#{k}=", v)
      end
    end

    # try to save the connected_client
    if connected_client.new_record? || connected_client.changed?
      unless connected_client.save
        send_response_error("Failed to add connected client")
      end
    end

    send_response_success()
    return
  end

  def get_config
    begin
      config = parse_post_json()
    rescue StandardError => e
      send_response_error(e.message)
      return
    end

    # Get AP MAC Address (REQUIRED)
    if (config.has_key? "mac")
      mac = config["mac"]
    else
      send_response_error("mac key not found")
      return
    end

    config_resp, err_msg = get_configuration(mac)

    if (!err_msg.nil?)
      send_response_error(err_msg)
      return
    end

    send_response(config_resp)
    return
  end

  def alive
    begin
      config = parse_post_json()
    rescue StandardError => e
      send_response_error(e.message)
      return
    end

    # Get AP MAC Address (REQUIRED)
    if (config.has_key? "mac")
      mac = config["mac"]
    else
      send_response_error("mac key not found")
      return
    end

    #get PI config hash (OPTIONAL)
    if (config.has_key? "config_hashes")
      pi_config_hash_array = config["config_hashes"]
    else
      pi_config_hash_array = nil
    end

    #get PI pmk hash (OPTIONAL)
    if (config.has_key? "pmk_hash")
      pi_pmk_hash = config["pmk_hash"]
    else
      pi_pmk_hash = nil
    end

    begin
      ap =  get_ap_by_mac(mac)
    rescue StandardError => e
      send_response_error("AP not found for passed MAC")
      return
    end

    # Set last time AP has been seen.
    ap.last_seen_at  = Time.now
    ap.save

    config_resp, err_msg = get_configuration(mac)

    if (!err_msg.nil?)
      send_response_error(err_msg)
      return
    end

    config_change_detected = false
    config_change_reasons = [ ]

    notes = [ ]

    # Iterate through all radios to see if hash exists or has changed.
    config_resp[:radios].each do |config_radio|
      radio_wlan_if = config_radio[:wlan]
      config_radio_hash = config_radio[:config_hash]

      sent_config_hash = pi_config_hash_array.try(:[], radio_wlan_if)
      if sent_config_hash.nil?
        config_change_reasons << "#{radio_wlan_if} needs update (hash not passed)"
        config_change_detected = true
      elsif config_radio_hash != sent_config_hash
        config_change_reasons << "#{radio_wlan_if} needs update"
        config_change_detected = true
      end
    end

    #Iterate through all config hashes sent. There could of been a radio removed
    pi_config_hash_array.keys.grep(/^wlan/).each do |pi_wlan|
      next unless config_resp[:radios].find { |h| h[:wlan] == pi_wlan}.nil?

      config_change_reasons << "#{pi_wlan} exists on pi, but radio if is not valid"
      config_change_detected = true
    end

    config_pmk_hash = config_resp[:pmk_hash]

    if ((pi_pmk_hash == nil) || (pi_pmk_hash != config_pmk_hash))
      config_change_detected = true
      config_change_reasons << "pmk needs update"
    end

    #if config changed, send update status
    ret = { }
    if (config_change_detected)
      ret[:status] = "update"
      ret[:notes] = config_change_reasons.join(", ")
    else
      ret[:status] = "success"
    end

    send_response(ret, "status: " + ret[:status])
    return
  end

  def update_wireless_clients
    logger.info("Starting Wireless Client Collection")

    begin
      clients = parse_post_json()
    rescue StandardError => e
      logger.info("Error in parsing json for update_wireless_clients")
      send_response_error(e.message)
      return
    end

    if (clients.has_key? "AP")
      ap = clients["AP"]
    else
      send_response_error("AP key not found")
      return
    end

    if (clients.has_key? "Stations")
      stations = clients["Stations"]
    else
      send_response_error("Stations key not found")
      return
    end

    # Look up access_point and profile
    ap_id = 0
    ap_profile_id = 0
    ap_rec = AccessPoint.find_by(mac: ap)
    if ap_rec
      ap_id = ap_rec.id
      ap_profile_id = ap_rec.access_point_profile_id
      ap_rec.channel_24 = nil
      ap_rec.channel_5 = nil
    end
    # update AP channel


    stations.each do | mac,station |
      # Get the existing station record if it's there
      a_station = WirelessClient.find_or_initialize_by(mac:mac)

      # Set the access point we found above
      a_station.access_point_id = ap_id

      # use the ssid to get the wlan and wlan controller
      if station.key? "ssid"
        wlan = AccessPointProfile.find(ap_profile_id).wlans.find_by(ssid: station["ssid"])
        a_station.wlan_id = wlan.id
        a_station.infrastructure_device_id = wlan.infrastructure_device_id
      end

      # Use the ARP table to lookup the ip and vlan
      if (arp_entry = ArpEntry.find_latest_for_mac(mac))
        a_station.ip = arp_entry.ip  # should be there
        a_station.vlan_id = arp_entry.vlan_id
      end

      # Transferthe information from the pi to the client record
      if station.key? "rx bytes"
        a_station.bytes_from_client = station["rx bytes"]
      end
      if station.key? "tx bytes"
        a_station.bytes_to_client = station["tx bytes"]
      end
      if station.key? "rx bitrate"
        a_station.rx_link_speed = station["rx bitrate"]
      end
      if station.key? "tx bitrate"
        a_station.tx_link_speed = station["tx bitrate"]
      end
      # For channel, also update AP
      if station.key? "channel"
        channel = station["channel"]
        a_station.channel = channel
        if channel < 15
          ap_rec.channel_24 = channel
        else
          ap_rec.channel_5 = channel
        end
      end

      if station.key? "signal avg"
        a_station.rssi = station["signal avg"]
      end
      if station.key? "vid"
        a_station.vlan_tag = station["vid"]
      end
      if station.key? "event"
        a_station.status = station["event"]
      end

      if station.key? "account"
        account = Account.find_by(login: station["account"])
        a_station.account_id = account.id
        logger.info("Skon:"+station["account"]+" #{account.id}")
      end

      if a_station.save
        logger.info("Skon : Wifi Station: Save successful")
      end
    end

    if ap_rec.save
      logger.info("Skon: AP Channel: Save successful")
    end

    # Get rid of old clients (nothing for 5 minutes)
    WirelessClient.where(updated_at: ..(5.minute.ago)).delete_all

    send_response_success

    return
  end

  protected
  ###############################################################################################
  # Local helper functions
  #
  ###############################################################################################
  def send_response(obj, html = nil)
    respond_to do |fmt|
      if html != nil
        fmt.html { render :plain => html }
      end

      if obj != nil
        fmt.json {
            render :json => obj.to_json
        }
      end
    end
  end

  def send_response_error(error_message)

    obj = {
      status: "fail",
      errmsg: error_message
    }
    send_response(obj, "error: " + error_message)
  end

  def send_response_success()

    obj = {
      status: "success"
    }
    send_response(obj, "success")
  end

  def parse_post_json
    if !request.post?
      raise "Expect a POST. Received other."
      return
    end

    if request.content_type != "application/json"
      raise "content type is not JSON. " + request.content_type
      return
    end

    json_data = request.body.read

    begin
      obj = JSON.parse(json_data)
    rescue JSON::ParserError
      raise "error parsing JSON"
      return
    end

    return obj
  end

  def get_ap_by_mac(mac)
    mac = Mac.clean_mac(mac)

    ap = AccessPoint.find_or_initialize_by(mac: mac)
    infdev = ap.infrastructure_device ||= WlanDevice.find_by(device: 'piglet')

    unless infdev
      raise "invalid WLAN controller configuration. Unable to find AP for mac #{mac}"
      return
    end
    return ap
  end

  def get_ap_profile_by_ap(ap)
    #Get infrastructure_device_id associated with AP's profile
    infrastructure_device_id = nil
    profiles = ap.effective_profiles();
    profiles.each do |profile|
      next if (profile == nil)
      return profile
    end
    return nil
  end

  def get_wlans_by_ap(ap, authentication: nil, encryption: nil)

    wlan_list = [ ]

    #Get infrastructure_device_id associated with AP's profile
    ap_profile = get_ap_profile_by_ap(ap)
    if ap_profile == nil
      return wlan_list
    end

    # Build list of WLAN's associated with the AP's effective Profile
    ap_profile.wlans.each do |wlan|
      next if (authentication != nil) && (wlan.authentication != authentication)
      next if (encryption != nil) && (wlan.encryption != encryption)
      wlan_list << wlan
    end

    return wlan_list
  end

  def set_pifi_error(ap, errmsg, save = false)
    if ap.pifi_error.nil?
      ap.pifi_error = errmsg
    else
      ap.pifi_error = ap.pifi_error + "\n" + errmsg
    end

    if save
      ap.save
    end
  end

  def get_configuration(mac)

    #Build initial Configuration
    config_resp = { }
    config_resp[:status] = "fail"
    config_resp[:radios] = [ ] #array of wlans

    wlan_id_list = [ ]

    #find AP associated with MAC
    begin
      ap =  get_ap_by_mac(mac)
    rescue StandardError => e
      return nil, "Cannot find AP by MAC: " + e.message
    end

    if (ap.approved != true)
      errmsg = "AP has not been approved by rXg"
      set_pifi_error(ap, errmsg, true)
      return nil, errmsg
    end

    # Get AP Profile
    ap_profile = get_ap_profile_by_ap(ap)
    if ap_profile.nil?
      errmsg  = "AP has no profile associated with it."
      set_pifi_error(ap, errmsg, true)
      return nil, errmsg
    end

    # set no errors
    ap.pifi_error = nil
    ap.save

    # Get radius server information
    if rso = RadiusServerOption.active
      config_resp[:radius_secret] = rso.secret
      config_resp[:radius_auth_port] = rso.auth_port
      config_resp[:radius_acct_port] = rso.acct_port
    end

    # There could exist a scenario where the AP Profile associated with the AP
    # does not have a radio profile, but one of the radios does? No
    # radio profile at the ap level isn't necessarily a base thing.
    ap_radio_profiles_prios = ap_profile.access_point_profiles_radio_profs

    ap_radio_profiles = nil

    # Find associated radio profiles
    if !ap_radio_profiles_prios.nil?
      ap_radio_profiles_prios.each do |rad_prio|
        prof = rad_prio.access_point_radio_profile

        radio_profile = { }
        radio_profile[:priority] = rad_prio.priority.to_i
        radio_profile[:wlan] = rad_prio.wlan
        radio_profile = radio_profile.merge(prof.attributes.to_hash.symbolize_keys)

        if ap_radio_profiles.nil?
          ap_radio_profiles = [ ]
        end
        ap_radio_profiles << radio_profile
      end
    end

    if ap_radio_profiles.nil?
      errmsg = "AP Profile does not have any 'AP Radio Profiles'"
      set_pifi_error(ap, errmsg, true)
      return nil, errmsg
    end

    # sort AP radio profiles by priority (descending, high to low)
    ap_radio_profiles = ap_radio_profiles.sort_by { |hsh| -hsh[:priority] }

    # Get a list of all radios, in WLAN interface descending
    radios = AccessPointRadio.where(:access_point_id => ap.id).order("wlan_if desc")

    if radios.nil? || (radios.size() == 0)
      errmsg = "AP does not have any radios associated with it."
      set_pifi_error(ap, errmsg, true)
      return nil, errmsg
    end

    # List of allocated channels on this AP. Used to detect multiple.
    channel_allocated_list = [ ]

    # iterate through all radios
    radios.each do |radio|
      radio_wlan_if = radio.wlan_if

      radio_config = {
        wlan:         radio_wlan_if
      }

      config = {
        mode:           "OFF"
      }

      radio_config[:config] = config

      # see if any ap_radio_profiles remain to be assigned
      if ap_radio_profiles.nil? || (ap_radio_profiles.size() == 0)
        radio_config[:note] = "No AP Profiles for WLANS remain to be assigned"
        radio_config[:config_hash] = Digest::MD5.hexdigest(JSON.generate(config))
        config_resp[:radios] << radio_config
        next
      end

      # Get first profile and drop it out of the profile list.
      radio_profile = ap_radio_profiles.shift

      # see if radio has a radio profile override associated with it

      if override_radio_profile = radio.access_point_radio_profile
        # we need to override the radio profile from the AP Profile with the one specific to the radio.
        radio_profile = radio_profile.merge(override_radio_profile.attributes.to_hash.symbolize_keys)
        radio_config[:note] = "Overriding Radio Profile with radio specific profile."
      end

      radio_config[:profile_note] = "radio_profile: '#{radio_profile[:name]}', priority #{radio_profile[:priority]}, hw_mode preference '#{radio_profile[:hw_mode_preference]}', channels '#{radio_profile[:selected_channels]}'."

      # Create array of hw modes "a,g,bng,etc.."
      hw_mode_preference = radio_profile[:hw_mode_preference].upcase
      hw_mode_preference = hw_mode_preference.delete ' '
      hw_mode_list = hw_mode_preference.split(",")

      # Get integer list of available channels on the radio
      radio_avail_channels = radio.avail_channels.split(",").map(&:to_i)

      # Get integer list of assignable channels for the radio from profiles (could include dashes)
      # radio_assignable_channels = radio_profile.selected_channels.split(",").map(&:to_i)
      radio_profile_assignable_channels = [ ]
      radio_profile[:selected_channels].split(",").each do |channel|
        if channel =~ /^([0-9]+)-([0-9]+)$/
          first = $1.to_i
          second = $2.to_i

          for ch in first..second
            radio_profile_assignable_channels << ch
          end
        elsif channel =~ /^([0-9]+)$/
          radio_profile_assignable_channels << $1.to_i
        end
      end

      channel_list = radio_profile_assignable_channels

      # Get list of possible channels by finding in common between available and assignable channels
      channels_possible = radio_avail_channels & radio_profile_assignable_channels

      if channels_possible.empty?
        errmsg = "[WLAN #{radio_wlan_if}]: No available channels for radio"
        radio_config[:error_msg] = errmsg
        radio_config[:config_hash] = Digest::MD5.hexdigest(JSON.generate(config))
        config_resp[:radios] << radio_config

        set_pifi_error(ap, errmsg)
        next
      end

      # remove any already allocated channels for the possible channel list
      if (channels_possible - channel_allocated_list).empty?
        radio_config[:channel_note] = "No unique channels available. Need to re-use"
      else
        # remove any already allocated channels for the possible channel list
        channels_possible = channels_possible - channel_allocated_list
      end

      hw_mode = nil

      # prefer to see if radio supports 5 Ghz (Channels 36-165)
      if channels_possible.grep(36..165).any?
        if hw_mode_list.at(0) == 'A'
          hw_mode = 'A'
          channels_possible = channels_possible.grep(36..165)
          channel_list = channel_list.grep(36..165)
        end
      end

      # next try tp see if radio supports 2.4 Ghz (Channels 1-11)
      if hw_mode.nil? && channels_possible.grep(1..11).any?
        if hw_mode_list.at(0) == 'B'
          hw_mode = 'B'
          channels_possible = channels_possible.grep(1..11)
          channel_list = channel_list.grep(1..11)
        elsif hw_mode_list.at(0) == 'G'
          hw_mode = 'G'
          channels_possible = channels_possible.grep(1..11)
          channel_list = channel_list.grep(1..11)
        end
      end

      if hw_mode.nil?
        errmsg = "[WLAN #{radio_wlan_if}]: hw mode could not be determined for radio"
        radio_config[:error_msg] = errmsg
        radio_config[:config_hash] = Digest::MD5.hexdigest(JSON.generate(config))
        config_resp[:radios] << radio_config

        set_pifi_error(ap, errmsg)
        next
      end

      # get radio mac as number ()
      radio_mac = radio.mac.delete ':' # remove mac separator : if there.
      radio_mac = "0x" + radio_mac     # prepend 0x for to_i to work
      radio_mac = radio_mac.to_i(16)   # convert base16 hex to int.

      # To get channel assignment, we use the mac addres to mod with length
      channel_idx = radio_mac % channels_possible.length
      channel = channels_possible.at(channel_idx)

      # Add channel to channel_allocated list.
      channel_allocated_list << channel

      if radio_profile[:wlan].nil?
        errmsg = "[WLAN #{radio_wlan_if}]: Radio Profile has no associated WLANS."
        radio_config[:error_msg] = errmsg
        radio_config[:config_hash] = Digest::MD5.hexdigest(JSON.generate(config))
        config_resp[:radios] << radio_config

        set_pifi_error(ap, errmsg)
        next
      end

      wlan_id_list << radio_profile[:wlan].id

      config_hostapd = {
        interface:    radio_wlan_if,
        ssid:         radio_profile[:wlan].ssid,
        hw_mode:      hw_mode.downcase,
        channel:      channel,
        channel_list: channels_possible.sort,
        open:         false
      }

      # if WLAN is open (no PSK)
      if radio_profile[:wlan].encryption == "none"
        config_hostapd[:open] = true
        config_hostapd[:open_vid] = radio_profile[:wlan].default_vlan
      end

      # If MAC Bypass authetication is used, the state machine needs to query
      # the radius server for a virtual tag assignment (VTA)
      if (radio_profile[:wlan].authentication == "mac") && (radio_profile[:wlan].encryption == "none")
        config_hostapd[:open] = true
        config_hostapd[:open_vid] = 4095
      end

      radio_config[:config][:mode] =     "AP"
      radio_config[:config][:hostapd] =  config_hostapd

      radio_config[:config_hash] = Digest::MD5.hexdigest(JSON.generate(config))

      config_resp[:radios] << radio_config
    end

    # check for unassigned radio profiles if we ran out of radios
    if ap_radio_profiles.size() > 0
      config_note = "No remaining radios to assign the following WLAN SSIDs:\n"
      ap_radio_profiles.each do |unassigned_ap_radio_profile|
        config_note = config_note + "#{unassigned_ap_radio_profile[:wlan].ssid} (priority #{unassigned_ap_radio_profile[:priority]})\n"
      end

      set_pifi_error(ap, config_note)
      config_resp[:warning] = config_note

    end

    begin
      pmk_list, pmk_hash = get_pmk(wlan_id_list: wlan_id_list)
    rescue Exception => e
      errmsg = "get_pmk error: #{e.message}."

      set_pifi_error(ap, errmsg)
      return nil, errmsg
    end

    config_resp[:status] = "success"

    config_resp[:pmk_hash] = pmk_hash
    config_resp[:pmk] = pmk_list

    # Do an AP Save here in case there are any changes to the pifi_error
    ap.save
    return config_resp, nil
  end

  def get_pmk(ssid: nil, wlan_id: nil, wlan_id_list: nil, return_hash: true, pmk_type: 'dpsk')
    # from LDD on 8/18
    #config=# select distinct ON (pmk, tag) accounts.login, ssid, pmk, decode(pmk, 'base64') as decoded_pmk, tag from pairwise_master_keys INNER JOIN accounts on accounts.id = pairwise_master_keys.account_id INNER JOIN vlan_tag_assignments ON accounts.id = vlan_tag_assignments.account_id ORDER BY pmk, tag;
    #ActiveRecord::Base.connection.execute("select distinct ON (pmk, tag) accounts.login, ssid, regexp_replace(pmk, E'[\\n\\r]+', '', 'g' ) as pmk, tag from pairwise_master_keys INNER JOIN accounts on accounts.id = pairwise_master_keys.account_id INNER JOIN vlan_tag_assignments ON accounts.id = vlan_tag_assignments.account_id ORDER BY pmk, tag;").to_a

    #create empty array for returned pmk/vlan hashes
    pmk_list = [ ]

    #find all PMKs associated with SSID
    if (ssid != nil)
      pmks = PairwiseMasterKey.where(
        ssid: ssid
      )
    elsif (wlan_id != nil)
      pmks = PairwiseMasterKey.where(
        wlan_id: wlan_id
      )
    elsif (wlan_id_list != nil)
      pmk_list = [ ]
      wlan_id_list = wlan_id_list.sort
      wlan_id_list.each do |wlan_id|
        wlan = Wlan.find_by(id: wlan_id)
        if wlan.authentication == "dpsk"
          # Call ourself recursively
          begin
            pmk_list += get_pmk(wlan_id: wlan_id, return_hash: false, pmk_type: "dpsk")
          rescue Exception => e
            raise e.message
          end
        elsif wlan.authentication == "mac" && wlan.encryption != "none"
          # Call ourself recursively
          begin
            pmk_list += get_pmk(wlan_id: wlan_id, return_hash: false, pmk_type: "mac")
          rescue Exception => e
            raise e.message
          end

        elsif wlan.authentication == "none"
          # Call ourself recursively
          if wlan.encryption != "none"
            begin
              pmk_list += get_pmk(wlan_id: wlan_id, return_hash: false, pmk_type: "psk")
            rescue Exception => e
              raise e.message
            end
          end
        else
          next
        end
      end

      #remove duplicates
      pmk_list = pmk_list.uniq

      pmk_hash = Digest::MD5.hexdigest(JSON.generate(pmk_list))

      if (return_hash)
        return pmk_list, pmk_hash
      else
        return pmk_list
      end
    else
      raise "getpmk: ssid, wlan_id and wlan_id_list cannot all be nil"
    end

    if pmk_type == 'psk'
      if wlan_id.nil?
        raise "getpmk: wlan_id not passed for type psk"
      end

      # find PMK for wlan_id
      pmk = PairwiseMasterKey.find_by(
        wlan_id: wlan_id
      )

      if pmk.nil?
        raise "PMK cannot be nil for wlan_id #{wlan_id}."
      end

      # find VLAN tag for WLAN
      wlan = Wlan.find_by(id: wlan_id)
      if wlan.nil?
        raise "WLAN cannot be nil for wlan_id #{wlan_id}."
      end

      vlan_tag = wlan[:default_vlan]

      pmk_item = {
        pmk: pmk.pmk.strip, #pmk from rxg has CR on end, need to remove it.
        vlanid: vlan_tag,
        pmk_note:  "type: psk, ssid: '#{wlan.ssid}'."
      }

      pmk_list << pmk_item
    elsif pmk_type == 'mac' # MAC Bypass authentication = virtual tag assignment via RADIUS
      if wlan_id.nil?
        raise "getpmk: wlan_id not passed for type psk"
      end

      # find PMK for wlan_id
      pmk = PairwiseMasterKey.find_by(
        wlan_id: wlan_id
      )

      if pmk.nil?
        raise "PMK cannot be nil for wlan_id #{wlan_id}."
      end

      # find VLAN tag for WLAN
      wlan = Wlan.find_by(id: wlan_id)
      if wlan.nil?
        raise "WLAN cannot be nil for wlan_id #{wlan_id}."
      end

      pmk_item = {
        pmk: pmk.pmk.strip, #pmk from rxg has CR on end, need to remove it.
        vlanid: 4095,   # 4095 indicates to Pifi to query radius for VLAN
        pmk_note:  "type: mac/vta, ssid: '#{wlan.ssid}'."
      }

      pmk_list << pmk_item
    elsif pmk_type == 'dpsk'
      wlan = Wlan.find_by(id: wlan_id)
      #iterate through PMK's associaed with ssid/wlan_id
      pmks.each do |pmk|
        # get account id related to PMK
        account_id = pmk[:account_id];

        #find account record associated with accountid
        account = Account.where(
          id: account_id
        ).first
        next if account == nil

        # make sure account is in active state
        next if account.state != 'active'

        #get VLAN ID corresponding to vlan table assignment to account_id
        vta_entry = VlanTagAssignment.where(
          account_id: account_id
        ).first
        next if vta_entry == nil

        pmk_item = {
         pmk: pmk.pmk.strip, #pmk from rxg has CR on end, need to remove it.
         vlanid: vta_entry.tag,
         ssid: wlan.ssid,
         pmk_note:  "type: dpsk, ssid: '#{wlan.ssid}'.",
        }

        # Add in account name if not nil
        if account.login
          pmk_item[:login] = account.login
        end
        pmk_list << pmk_item
      end
    else
      raise "getpmk: unknown pmktype '#{pmktype}'. Possible values are 'psk' and 'dpsk'"
    end

    if (return_hash)
      return pmk_list, pmk_hash
    else
      return pmk_list
    end
  end
end
