#!/usr/bin/ruby
require 'set'
require 'ipaddr'
#########################################################################################
# Bugs to address / think about
# jmb - in start() for processes, should it look to kill the process if already running?
#########################################################################################
########################################################################################
# Version - of the form major.minor.revision
########################################################################################
MAJOR = 1
MINOR = 0
REVISION = 9

require 'active_support/core_ext/object/blank'

# PiFi State Machine Code
require 'rubygems'
require 'httparty'
require 'json'
require 'logger'
require 'fileutils'

# Number of retries on message failure from the rXg
RXG_RETRIES = 10

# Number of times to attempt to restart a process
PROC_RESTART_RETRIES = 5

# Pifi current HASHES
cur_config_hash = "FFFFFFFFFFFFFFF"
cur_pmk_hash = "FFFFFFFFFFFFFFF"

# PiFI current connection states
@connection_states = {}

# PMK file uname
PMK_FILE = "/etc/hostapd/hostapd.wpa_pmk_file"

# hostapd.conf
HOSTAPD_FILE = "/etc/hostapd/hostapd.conf"

#################################################################
# puts and print overrides to redirect to logging engine.
#################################################################
$logger = nil
def puts(o1, o2 = nil, o3 = nil)
  line = o1.to_s
  if !o2.nil? then line += o2.to_s end
  if !o3.nil? then line += o3.to_s end

  line = line.strip

  # Removes all unprintable characters from a line.
  line = line.gsub(/[^[:print:]]/,'')

  if line.length == 0
    return
  end

  #output to STDOUT
  super(line)

  #output to log file
  if !$logger.nil?
    $logger.info(line)
  end
end

def print(o1, o2 = nil, o3 = nil, o4 = nil, o5 = nil, o6=nil)
  line = o1.to_s
  if !o2.nil? then line += o2.to_s end
  if !o3.nil? then line += o3.to_s end
  if !o4.nil? then line += o4.to_s end
  if !o5.nil? then line += o5.to_s end
  if !o6.nil? then line += o6.to_s end

  # Call above override.
  puts(line)
end

#################################################################
#
# State Machine States
#
#################################################################
module STATES
  START     = 0   # Waiting from approval
  CONFIG    = 1   # Waiting for config
  HEALTH    = 2   # Heath notice - bad config or pmk
  RUN       = 3   # AP is running
  DISABLING = 4   # Need to disable radios
  WAITGW    = 5   # Wait for gateway address
end

module PROCESS_STATES
  DOWN   = 0  # This instance is not running
  RUN    = 1 # This instance is running
end

module WLAN_STATES
  OFF = 0 # Not bring used
  AP = 1 # Being used as an AP
  SCAN = 2 # Being used for monitoring
  WAIT_AP = 4 # Waiting to start as AP
end

#################################################################
#
# A class for managing and monitoring hostapd instances
#
#################################################################
class Hostapd_instance
  def initialize(wlan)
    @pid = 0
    @conf_file = "/etc/hostapd/hostapd."+wlan+".conf"
    @wlan = wlan
    @state = WLAN_STATES::OFF
    @thread = nil
    @ssid = ""
  end

  def is_running
    if @pid==0
      return false
    end
    print "PID " + @pid.to_s + " "
    cmd = "kill -0 " + @pid.to_s
    result = `#{cmd}`
    if $?.success?
      print  @wlan," hostapd running","\n"
      return true
    else
      @pid = 0
      print @wlan,"hostapd not running","\n"
      return false
    end
  end

  def state
    return @state
  end

  def wlan
    return @wlan
  end

  def set_ssid(ssid)
    @ssid = ssid
  end

  def ssid
    return @ssid
  end

  def set_to_start
    @state = WLAN_STATES::WAIT_AP
  end
  
  def run_or_hup(state)
    # See if running
    if self.is_running
      print  @wlan,"hostapd HUP the process","\n"
      cmd = "kill -HUP " + @pid.to_s
      `#{ cmd }`
    else
      print "Start the HOSTAPD process for ",@wlan,"\n"

      cmd = "/usr/sbin/hostapd -f /var/log/pifi/hostapd.#{@wlan}.log #{@conf_file}"
      @pid = Process.spawn(cmd)
      Process.detach(@pid)

      print "Start hostapd for ",@wlan,"PID:",@pid,"\n"
    end
      @state = state
  end

  def stop()
    if @pid > 0 and is_running
      print "Stopping hostapd for ",@wlan," pid: " ,@pid,".\n"
      cmd = "kill -9 " + @pid.to_s
      `#{ cmd }`
      @pid = 0

      #also we need to down wlan or else SSID is still broadcast
      cmd = "ifconfig #{@wlan} down"
      `#{ cmd }`
      cmd = "ifconfig #{@wlan} up"
      `#{ cmd }`
      

    end
      @state = WLAN_STATES::OFF
  end

  def get_pid
    return pid
  end
end

#################################################################
#
# A class for managing and monitoring wlanbridge instance
#
#################################################################
class Wlanbridge_instance
  def initialize
    @pid = 0
    @wlan = ""
    @state = PROCESS_STATES::DOWN
    @thread = nil
  end

  def is_running
    if @pid==0
      return false
    end
    print "Bridge PID " + @pid.to_s + " "
    cmd = "kill -0 " + @pid.to_s
    result = `#{cmd}`
    if $?.success?
      #puts "Running"
      return true
    else
      @pid = 0
      #puts "Not Running"
      return false
    end
  end

  def run(wlans,static_vids)
    @wlans = wlans

    puts "Start the wlanbridge process"
    cmd = '/opt/wlanbridge/bridge eth0 '
    wlans.each do | wlan |
      if static_vids.key?(wlan)
        puts "static_vids[wlan]: "+ static_vids[wlan].inspect
        STDOUT.flush
        cmd = cmd + wlan + ":" + static_vids[wlan][:static_vid].to_s + ":" + static_vids[wlan][:ssid].to_s + " "
      else
        cmd = cmd + wlan + " "
      end
    end

    cmd = cmd + " -f /var/log/pifi/wlanbridge.log"
    puts cmd

    @pid = Process.spawn(cmd)
    Process.detach(@pid)

    print "Start wlanbridge: ",@pid," on ",wlans.to_s,"\n"
    @state = PROCESS_STATES::RUN
  end

  def stop()
    if @pid > 0 and is_running
      print "Stopping wlanbridge: ",@pid," on ",@wlan,"\n"
      cmd = "kill -9 " + @pid.to_s
      `#{ cmd }`
      @pid = 0
    end
    @state = PROCESS_STATES::DOWN
  end

  def get_pid
    return pid
  end
end


#################################################################
#
# A class for keeping track of a radius client instance
#
#################################################################
class Radiusclient_instance
  def initialize
    @pid = 0
    @state = PROCESS_STATES::DOWN
    @thread = nil

    @radius_server = nil
    @radius_secret = nil
  end

  def is_running
    if @pid==0
      return false
    end

    print "Checking Radius Client PID " + @pid.to_s + " "
    retval = !!Process.kill(0, @pid) rescue false
    return retval
  end

  def set_params(radius_server: nil, radius_secret: nil)
    if !radius_server.nil?
      @radius_server = radius_server
    end

    if !radius_secret.nil?
      @radius_secret = radius_secret
    end

  end

  def run()

    # check if already running
    if @pid > 0 and is_running
      self.stop()
    end


    # for stdout pipe redirection thread, kill if running
    if (@thread != nil)
      Thread.kill(@thread)
      @thread = nil
    end

    puts "Start the Radius Client process"

    #cmd = "./radius_client.rb"
    cmd = "ruby #{__dir__}/radius_client.rb"
    if !@radius_server.nil?
      cmd = cmd + " --server #{@radius_server}"
    end

    if !@radius_secret.nil?
      cmd = cmd + " --secret #{@radius_secret}"
    end

    puts "Starting RADIUS client: '#{cmd}'"

    # create IO pipe reader/writer to redirect STDOUT from spawned process to the state machine
    reader, writer = IO.pipe

    @pid = Process.spawn(cmd, :chdir=>__dir__, :out => writer, :err => writer)
    Process.detach(@pid)

    #this thread reads the output of the above spawned process and redirects it to STDOUT
    writer.close
    @thread = Thread.new do
      loop do
        begin
          begin
            lines = reader.read_nonblock(4096)
          rescue EOFError # EOF Error is when process is killed.
            @thread = nil
            Thread.exit()
          end

          lines.split(/\n/).each do |line|
            line = line.strip
            if line.length > 0
              print "[RADIUSCLIENT #{@pid}] '#{line}'\n"
            end
          end

        rescue IO::WaitReadable
          #IO.select([io])
          #retry
        end
        sleep (0.1)
      end
    end

    print "Start radius client: #{@pid}\n"
    @state = PROCESS_STATES::RUN
  end

  def stop()
    if @pid > 0 and is_running
      puts "Stopping radius client: #{@pid}."
      cmd = "kill -9 " + @pid.to_s
      `#{ cmd }`
      @pid = 0
    end
    @state = PROCESS_STATES::DOWN
  end

  def get_pid
    return pid
  end
end




#################################################################
#
# State: A class for state representation and management
#
#################################################################
class State
  def initialize(state, sleep_time = 30)
    @my_state=state
    @changed=true
    @last_run_time_ms = 0
    @sleep_time_secs = sleep_time # in seconds
    @pause_between_state_change = false
  end

  def update(state, should_pause = false)
    if state != @my_state
      @my_state=state
      @changed=true
      @pause_between_state_change = should_pause
    end
  end

  def get
    return @my_state
  end

  def is_changed
    if @changed
      @changed=false
      return true
    end
    return false
  end

  def should_sleep
    return @pause_between_state_change
  end

  def now_ms
    return Process.clock_gettime(Process::CLOCK_MONOTONIC) * 1000
  end

  def set_poll_time(poll_time_secs)
    #Make sure passed param can be converted into an integer. (i.e. catch NIL, etc)
    poll_time_secs = Integer(poll_time_secs) rescue false
    if (poll_time_secs === false)
      return
    end

    # We never want poll time to be less than 0.
    if (poll_time_secs == 0)
      return
    end

    @sleep_time_secs = poll_time_secs
  end

  def sleep
    sleep_time_ms = (@sleep_time_secs*1000 ) - (now_ms() - @last_run_time_ms)
    sleep_time_ms = sleep_time_ms.round

    if (sleep_time_ms > 0)
      puts "sleeping #{sleep_time_ms} ms"
      Kernel.sleep(sleep_time_ms.to_f / 1000)
    end
    @last_run_time_ms = now_ms()
  end
end

module MESSAGES
  HELLO   = '/pifi/hello.json'
end

#################################################################
#
# Default Config - a template for hostapd configurations
#
#################################################################
DEFAULT_CONFIG= { country_code: "US",
                  interface: "dummy",
                  driver: "nl80211",
                  ssid: "rgnetspifi",
                  ignore_broadcast_ssid: 0,
                  ieee80211d: 1,
                  hw_mode: "g",
                  ieee80211n: 1,
                  require_ht: 1,
                  ieee80211ac: 1,
                  channel: 11,
                  wpa: 2,
                  auth_algs: 1,
                  wpa_key_mgmt: "WPA-PSK",
                  rsn_pairwise: "CCMP",
                  wpa_pairwise: "CCMP",
                  wpa_passphrase: "rxgdefault",
                  wmm_enabled: 1,
                  wpa_psk_file: "/etc/hostapd/hostapd.wpa_pmk_file"
                  }


# Default rate for time between hellos (seconds)
DEFAULT_RATE = 5
# time between station list (seconds)
STATION_SCAN_TIME = 30

# Get our gateway address
def get_gateway
  gw=`ip route | awk '/default/{print $3; exit}'`.chomp.presence || nil
  begin
    r = IPAddr.new gw
  rescue IPAddr::InvalidAddressError
    puts "BAD Gateway"
    return nil
  end
  return r.to_s
end

# Get ethernet MAC address
def get_mac_address
  platform = RUBY_PLATFORM.downcase
  mac=`ip link show dev eth0 | awk '/link/{print $2}'`
  return mac.chomp
end

def get_os()
  os = `uname -r`
  return os.strip
end

def get_piglet_version()
  cmd = `apt info piglet 2>/dev/null`

  if cmd =~ /Version:\s+(.+)/
    return $1.strip
  end
  return nil
end

def get_cpu_info ()
  serial = `awk '/Serial/{print $3}' /proc/cpuinfo`.chomp
  model = `awk '/Model/{$1=$2=""; print $0}' /proc/cpuinfo`.chomp.lstrip
  return {'serial' => serial, 'model' => model }
end

def get_wlan_list ()
  output = `iw dev`
  iwDev = output.split("\n")
  interfaces = Array.new
  i = 0
  while  i < iwDev.length() do
    if iwDev[i] =~ /^phy#(\d)/
      phy = "phy"+$1
      i = i + 1
      while i < iwDev.length() and not iwDev[i] =~ /^phy#\d/ do
        if iwDev[i] =~	/\s+Interface (wlan\d)/
          interface=$1
        end
        if iwDev[i] =~ /addr ([a-fA-F0-9:]{17}|[a-fA-F0-9]{12})/
          mac = $1
        end
        if iwDev[i] =~ /.+type (\w+)/
          type = $1
        end
        if iwDev[i] =~ /.+txpower ([\d.]+)/
          txpower = $1
        end
        i = i + 1
      end
      if type == "managed" or type == "AP"
        interfaces.append({wlan: interface, phy: phy, mac: mac, txpower: txpower})
      end
    end
  end
  return interfaces
end

# Gather all the information about wifi hardware
def gather_wlan_info()
  interfaces = get_wlan_list
  wlans = Array.new
  interfaces.each  { |i_hash|
    bands =  get_wlan_bands(i_hash[:phy])
    i_hash = i_hash.merge(bands)
    wlans.append(i_hash)
  }
  return wlans
end

# Get modes and channel list of a given wifi device
def get_wlan_bands(phy)
  iwlist = `iw list`
  # Find the interface
  lines=iwlist.split(/\n+/)
  i = 0
  while i < lines.length() and not lines[i].include? "Wiphy "+phy
    i=i+1
  end
  i=i+1

  # find each band
  bands = Hash.new
  while i < lines.length() and not lines[i].include? "Wiphy "
    if lines[i]  =~ /^\s*Band\s(\d):.*/
      band = $1

      i = i + 1
      channels = Array.new
      caps = Array.new
      freqs = Array.new
      power = Array.new
      # Get capabilities for a band
      while i < lines.length() and not lines[i] =~ /^\s*Band (\d):.*/ and not lines[i].include? ("Supported commands:") and not lines[i].include?("Wiphy ")
        # Find capabilities
        if lines[i].include?("Capabilities: 0x")
          i = i + 1
          while not lines[i].include?("Maximum") and lines[i] =~ /^\s+(\w.+)$/
            caps.push($1)
            i = i + 1
          end
        end

        if lines[i].include?("Frequencies")
          i = i + 1
          while lines[i] =~ /^\s+\* \d+\sMHz/
            if not lines[i].include?("disabled") and not lines[i].include?("radar") and not lines[i].include?("no IR")
              if lines[i] =~ /^\s+\* (\d+)\sMHz\s\[(\d+)\]\s+\(([\d.]+)/
                channels.push($2)
                freqs.push($1)
                power.push($3)
              end
            end
            i = i + 1
          end
        end
        if i < lines.length() and not lines[i]  =~ /^\s*Band\s(\d):.*/ and not lines[i].include?("Wiphy ")
          i = i + 1
        end
      end
      # Finsh up a band
      bands["band"+band]={:channels=>channels,:freqencies=>freqs,:power=>power,:capabilities=>caps}

    end
    if i < lines.length() and not lines[i]  =~ /^\s*Band\s(\d):.*/ and not lines[i].include?("Wiphy ")
      i = i + 1
    end
  end
  return bands
end

# Get the maximum interface number of the wlans
def get_max_wlan ()
  output = `ip link show`

  interfaces = Array.new
  i=0
  max_index=-1
  max_interface = "none"
  output.each_line do |line|
    #look for lines with wlan in it. Index of interface is in $1, index of wlan is in $2
    next unless line =~ /^([0-9]+):\swlan([0-9]+):/

    index = $2.to_i
    if (index > max_index)
      max_index = index
      max_interface = "wlan#{index}"
    end
  end
  return max_interface
end

# Get modes and channel list
def get_hw_info
  iwlist = `iw list`
  max_if = "phy0"

  # find max interface
  iwlist.each_line do |line|
    if line =~ /Wiphy/
      i = line =~ / phy/
      if i
        itf = line[i+1..-1].chomp
        max_if = max_if > itf ? max_if : itf
      end
    end
  end
  # Find the interface
  lines=iwlist.split(/\n+/)
  i = 0
  while i < lines.length() and not lines[i].include? max_if
    i=i+1
  end
  i=i+1

  # Find the frequencies
  # g is for channels under 15,
  # a for other channels (for now)
  chan_a = Array.new
  chan_g = Array.new
  while i < lines.length() and not lines[i].include? "Wiphy phy"

    # ignore radar for now
    if  not lines[i].include? "radar" and not lines[i].include? "disable"
      chan_info = lines[i].scan /(\s\*\s\d+\sMHz\s\[)(\d+)/

      if  chan_info.instance_of? Array  and chan_info.any?
        chan = chan_info[0][1].to_i
        if chan <= 14
          chan_g.push(chan)
        else
          chan_a.push(chan)
        end
      end
    end
    i=i+1
  end
  result = {:g=>chan_g,:a=>chan_a}
  return result
end

###########################################################
# get_stations - given an interface return a list of stations
# Including all information available.  Minimum is MAC addresses
############################################################
def get_stations(interface,channel)
  @cmd = "iw dev #{interface} station dump"
  puts @cmd
  @station_list = `#{ @cmd }`
  @lines = @station_list.split("\n")
  @stations = {}
  @station = {}
  @mac = ""
  i = 0
  while i < @lines.length() do
    #puts @lines[i]
    # if this is a new station, save the old
    if @lines[i] =~ /Station\s/ and @mac.length > 0
      @stations[@mac] = @station
      @station = {}
      @mac = ""
    end
    if @lines[i] =~ /Station\s(.+)\s\(on (.+)\)/
      @mac = $1
      @station["interface"] = $2
      @station["channel"]=channel
    end
    if @lines[i] =~ /\s(.+):\s(.+)/
      @station[$1] = $2.strip
    end
    i = i + 1
  end
  if @mac.length > 0
    @stations[@mac] = @station
  end
  return @stations
end

# Given a list of interfaces gather all station (client) information
# Into a hash
# Send a hash of wlans and channels.
def gather_station_info(interface_channels,connection_states,hostapd_procs)

  # Get the current connection states from the connetion log
  update_connections(connection_states)
  #puts "CONNECTIONS:"+connection_states.to_s

  @all_stations = {}
  interface_channels.each { | wlan, channel |
    #get the stations for a given wlan
    @stations = get_stations(wlan,channel)

    # Merge results with latest connection state
    @stations.each { | mac, station |
      station_state = connection_states[mac]
      #puts "STATION STATE #{mac} #{station_state}"
      #puts "STATION DATA #{@stations[mac]}"
      if not station_state.nil?
        @stations[mac] = @stations[mac].merge(station_state)
      end
      @stations[mac]["ssid"] = hostapd_procs[@stations[mac]["interface"]].ssid
    }

    @all_stations = @all_stations.merge(@stations)
    # Add in all disconnected stations if we were already assocated
    #connection_states.each { | mac, station |
    #  if station["event"] == "disassoc"
    #    @all_stations[mac] = station
    #  end
    #}
    puts "STATIONS: #{ @all_stations }"

    # Clear connection states for stations no longer present
    #connection_states.keys.each { | mac |
    #  if not @all_stations.key? mac
    #    connection_states.delete(mac)
    #    puts "Delete #{mac} from connection states"
    #  end
    #}
  }
  return @all_stations
end

#######################################################################
# read connections log and clear it
#######################################################################
CONNECTION_LOG = "/tmp/connections.json"

def update_connections(connections)
  begin
    File.open(CONNECTION_LOG).each do |line|
      connection = JSON.parse(line)
      if connection.key? "mac"
        mac = connection["mac"].downcase
        connections[mac] = connection
      end
    end
    # Clear the file
    File.open(CONNECTION_LOG,'w') {|file| file.truncate(0) }

  rescue
    puts "ERROR is processing connections.json file"
    # nothing else to do here
  end
end


#######################################################################
# Local AP scanning and Auto channel setting code
#######################################################################
# Channels that overlap. we only use 1, 6, 11
OVERLAPPING_CHANNELS = {2 => [1,6], 3 => [1,6], 4 => [1,6], 5 => [1,6], 7 => [6,1],
                        8 => [6,11], 9 => [6,11], 10 => [6,11], 12 => [11,14],
                        13 => [11,14]}

#######################################################################
# overlap_channels - return the real channels this channel affect
#######################################################################
def overlap_channels(channel)
  if OVERLAPPING_CHANNELS.key?(channel)
    print "Fucking overlapping channel: ",channel,"\n"
    return OVERLAPPING_CHANNELS[channel]
  else
    return[channel]
  end
end

#######################################################################
# get_ap_list - Get a list of APs visible as a hash over AP addresses
# interface is the interface to use to do the scan
#######################################################################
def scan_for_aps (interface)
    # First let's make sure the interface is up
    cmd = "ifconfig #{interface} up"
    print "Bringing up interface: #{ cmd }\n"
    `#{ cmd }`

    @ap_list = `iw dev #{interface} scan`
    @lines = @ap_list.split("\n")
    @ap_data = {}
    @address = ""
    @ssid = ""
    @channel = ""
    @signal=""
    @frequency = ""
    @ht_width = ""
    @ht_protection = ""
    i = 0
    while i < @lines.length() do
      if @lines[i] =~ /BSS (.+)\(/
        if @address != ""
          # Convert overlapping channels to actual channel(s)
          @cell = {"SSID" => @ssid, "channel" => @channel,
                   "frequency" => @frequency, "ht_width" => @ht_width,
                   "signal" => @signal, "ht_protection" => @ht_protection}
          @ap_data[@address] = @cell

          # Clear out for next
          @address = ""
          @ssid = ""
          @channel = ""
          @signal=""
          @frequency = ""
          @ht_width = ""
          @ht_protection = ""
        end
        @address = $1
      end
      if @lines[i] =~ /\sSSID: (.+)/
        @ssid = $1
      end
      if @lines[i] =~ /\sprimary channel: (\d+)/
        @channel = $1.to_i
      end
      if @lines[i] =~ /\sfreq: (.+)/
        @frequency = $1
      end
      if @lines[i] =~ /\ssignal: (.+) dBm/
        @signal = $1.to_f
      end
      if @lines[i] =~ /\s* STA channel width: (.+)/
        @ht_width = $1
      end
      if @lines[i] =~ /\s* HT protection: (.+)/
        @ht_protection = $1
      end
      i += 1
    end
    if not @ap_data.key?(@address)
      @cell = {"SSID" => @ssid, "channel" => @channel,
               "frequency" => @frequency, "ht_width" => @ht_width,
               "signal" => @signal, "ht_protection" => @ht_protection}
      @ap_data[@address] = @cell
    end
    if @address != ""
      return @ap_data
    end
end



#######################################################################
# select channel - find a channel for a interface
# interface - the channel to select for. A scan will be done on this
#             interface, so the interface MUST BE down (no hostapd running)
# band - the band to use (G or A)
# channels - the list of channels the rXg says we can choose from
#
#######################################################################

def select_channel(interface,channels,channel)
  # Check for corner cases
  if channels.length() == 0
    return channel
  end
  if channels.length() == 1
    return channels[0]
  end

  @avail_channels = channels.to_set

  @scan = scan_for_aps(interface)
  #print @scan,"\n"
  if @scan.nil?
    print "No APs found, choosing a random station\n"
    return channels.shuffle.first
  end
  # create a hash of ap channels, and the signal strengths
  # If the channel already exists with a stronger signal, ignore weaker
  @channel_levels = {}
  @used_channels = Set[]
  @scan.each do |mac,info|
    # convert overlapping channels into two real channels
    @chans = overlap_channels(info["channel"])
    @chans.each do |chan|
      @used_channels.add(chan)
      if @channel_levels.key?(chan)
        if  @channel_levels[chan] < info["signal"]
          @channel_levels[chan]= info["signal"]
        end
      else
        @channel_levels[chan]= info["signal"]
      end
    end
  end
  puts @channel_levels
  print "In use:", @used_channels, "\n"
  @unused = @avail_channels - @used_channels
  print "unused:", @unused, "\n"
  if @unused.length > 0
    return @unused.to_a.shuffle.first
  end
  puts "No unused channels, finding best"

  # Scan through channels to find the one with the weakest signal
  @least_channel = 0
  @least_signal = 0
  @channel_levels.each do | chan, sig |
    if @avail_channels.include?(chan)  and sig < @least_signal
      @least_signal = sig
      @least_channel = chan
    end
  end
  return @least_channel

end


#################################################################
#
# rXg message functions
# These function create message to push to the
# pifi rXg contoller endpoint
#
#################################################################

# send message to rXg. Expect JSON in return.
def send_rxg_request(rXg,endpoint, postdata)
  body = postdata.to_json

  #rXg = "192.168.1.250"

  url = 'https://'+rXg++'/pifi/' + endpoint
  #puts "url: #{url}"
  header = { 'Content-Type' => 'application/json' }

  response_error = {
    status:   "httperror",
    error:    nil
  }

  begin
    result = Client.post(url,
                         body: body,
                         headers: header,
                         timeout: 5         #timeout is in seconds
                        )
  rescue HTTParty::Error, SocketError => e
    response_error[:error] = "HTTParty::Error: #{ e.messages} "
    return response_error
  rescue StandardError => error
    response_error[:error] = "HTTParty::Error: #{error}"
    return response_error
  end

  if (result.code != 200)
    response_error[:error] = "HTTParty: non 200 error: #{result.code}"
    return response_error
  end

  begin
    result.parsed_response
  rescue JSON::ParserError => e
    response_error[:error] = "JSON::Error: #{ e.messages} "
    return response_error
  end

  return result.parsed_response;
end

# Send a hello message to the rXg
def send_rxg_hello_mesg(rXg,mac)
  wlan=get_max_wlan()
  os=get_os();

  piglet_version = get_piglet_version()

  cpu=get_cpu_info
  # get radio info
  channels=get_hw_info().to_json
  wlans = gather_wlan_info
  version_str = MAJOR.to_s+"."+MINOR.to_s+"."+REVISION.to_s
  puts "VERSION: #{version_str}"
  body = { mac: mac,
           version: version_str,
           ap_info: {
             wlans: wlans,
             os: os,
             model: cpu['model'],
             serial: cpu['serial'],
           }
         }

  print "Hello: ", body.to_json,"\n"
  result = send_rxg_request(rXg, "hello.json", body)

  return result
end

# Send a config message to the rXg
def send_rxg_conf_mesg(rXg,mac,conf_hashes,pmk_hash)
  config = { mac: mac,
             config_hashes: conf_hashes,
             pmk_hash: pmk_hash
           }
  print "Config request:", config.to_json,"\n"

  result = send_rxg_request(rXg, "get_config.json", config)
  print "Config results:",result.to_json,"\n"
  return result
end

# Send an alivemessage to the rXg
def send_rxg_alive_mesg(rXg,mac,conf_hashes,pmk_hash,channels,uptime)
  alive = { mac: mac,
            config_hashes: conf_hashes,
            pmk_hash: pmk_hash,
            channels: channels,
            uptime: uptime
          }
  print "Alive  request:", alive.to_json,"\n"

  result = send_rxg_request(rXg,"alive.json", alive)
  return result
end

# Send an wireless clients message to the rXg
def send_rxg_clients_mesg(rXg,clients)
  result = send_rxg_request(rXg,"update_wireless_clients.json", clients)
  return result
end


# Class to allow unchecked https
class Client
  include HTTParty

  #verify:false disables SSL cert checking
  default_options.update(verify: false)
end

#################################################################
#
# write pmk file - write a pmk list recieved from rXg to a file
#
#################################################################
def write_pmk(hash,pmks)
  #puts "PMK:",hash,pmks
  # Write out the new file
  File.open(PMK_FILE,"w") { |f|
    f.write("# Hash: "+hash+"\n")
    f.write("# Warning - This file is auto generated.  Do not modify\n")
    pmks.each do |pmk_entry|
      if pmk_entry.key?("login") and pmk_entry.key?("vlanid") and pmk_entry.key?("pmk")
        f.write("login="+pmk_entry["login"]+" vlanid="+pmk_entry["vlanid"].to_s+" pmk="+pmk_entry["pmk"]+"\n")
      elsif pmk_entry.key?("vlanid") and pmk_entry.key?("pmk") # No Login/account association (Normal for PSK WLAN)
        f.write("vlanid="+pmk_entry["vlanid"].to_s+" pmk="+pmk_entry["pmk"]+"\n")
      else
        puts "Bad PMK entry: #{ pmk_entry }"
      end
    end
  }
end


#################################################################
#
# write config - write a new hostapd.conf from information from rXg
# Returns static VLAN number or -1, ssid or "", channel or ""
#
#################################################################
def write_config(hash,config,hostapd_procs)
  print "Configuration sent: ",config,"\n"
  @chan_list = []
  @auto_channel = 0
  new_config = DEFAULT_CONFIG.dup
  channel = false
  static_vid = -1
  ssid = nil

  config.each do | key,value |

    case key
    when "ssid"
      new_config[:ssid] = value
      @ssid = value
    when "interface"
      new_config[:interface] = value
      @interface = value

    when "channel"
      if not value.nil?
        new_config[:channel] = value
        @auto_channel = value
      end

    when "hw_mode"
      if not value.nil?
        new_config[:hw_mode] = value.downcase
      end

    when "channel_24"
      if not value.nil?
        new_config[:channel] = value
        channel = true
        new_config[:hw_mode] = "g"
      end

    when "channel_5"
      if not channel and not value.nil?
        new_config[:channel] = value.to_s
        channel = true
        new_config[:hw_mode] = "a"
      end

    when "open"
      # if OpenSSID (no PSK) delete all WPA attributes
      if !value.nil? && value == true
        new_config.delete(:wpa)
        new_config.delete(:auth_algs)
        new_config.delete(:wpa_key_mgmt)
        new_config.delete(:rsn_pairwise)
        new_config.delete(:wpa_pairwise)
        new_config.delete(:wpa_passphrase)
        new_config.delete(:wpa_psk_file)
      end

    when "open_vid"
      if not value.nil?
        static_vid = value
      end

    when "channel_list"
      if not value.nil?
        @chan_list = value
      end

    else
      if value.nil?
        value = "nil"
      end
      print "Ignoring: " + key + " = " + value.to_s + "\n"
    end
  end

  if not @ssid.nil? and not @interface.nil?
    hostapd_procs[@interface].set_ssid(@ssid)
  end

  # We have a config, now we need to pick a channel if we got a list of channels
  print "########################## Auto Channel selection ################\n"
  if @chan_list.length > 0
    print "candidate channels:", @chan_list, "\n"
    # Stop the wlan for channel scan
    if not hostapd_procs.nil?() and hostapd_procs.key?(@interface) and hostapd_procs[@interface].is_running()
      hostapd_procs[@interface].stop()
    end
    @auto_channel = select_channel(@interface,@chan_list,channel)
    print "Auto channel: ", @auto_channel,"\n"
    new_config[:channel] = @auto_channel
  end



  print "New Config",new_config,"\n"
  # Write out the new file
  config_file = "/etc/hostapd/hostapd."+new_config[:interface]+".conf"
  File.open(config_file,"w") { |f|
    f.write("# Hash: "+hash+"\n")
    f.write("# Warning - This file is auto generated.  Do not modify\n")
    f.write("ctrl_interface=/var/run/hostapd\n")
    new_config.each do |key,value|
      if not value.nil?
        f.write(key.to_s+"="+value.to_s+"\n")
      end
    end
  }
  return static_vid, ssid, @auto_channel

end

# Delete /etc/hostapd/hostap.conf/
# These won't be needed once we put file in ram dick
# TODO
def clear_ap_config
end

# delete /etc/hostapd.wpa_pmk_file
# TODO
def clear_pmk_file
end

#################################################################
#
# Process the passed poll wait time
#
#################################################################
def process_wait_time(wait,data)
  if data.nil? then return nil end

  if data.key?('poll_time')
    new_wait=result['poll_timer'].to_i
    if new_wait.is_a? Integer
      wait = new_wait
      print "New wait time: ",wait,"\n"
      wait = 5 # force to 5 for testing
    end
  end
  return wait
end



#################################################################
#
# PiFiState Machine
# Main routine for managing pifi AP states for multiple interfaces
# This process runs forever, managing system states and keeeping
# the system in regular communication with the rXg
# This process allows the local device to be the active agent
# in managing a PiFi device, while the rXg is a passive partner
# responding to PiFi messages
#
#################################################################
@should_run = true
def pifi_management
  # A place to store our current channel to wlan association
  @channels = {}
  # Used to keep the uptime in seconds
  @uptime = 0
  # stores the time the AP started, 0 means not started
  @start_time = 0
  # kill hostapd, wlanbridge and radius client by name
  `pkill -f hostapd`
  `pkill -f wlanbridge`
  `pkill -f radius_client.rb`

  #sleep to allow system to recover from killing hostapd and wlanbridge.
  sleep(1)

  # The latest config and pmk hash
  config_hashes = Hash.new
  pmk_hash = "FFFFFFFFFFFF"
  pmk_file = nil
  new_pmk = false

  # Create objects to manage processes
  hostapd_procs = Hash.new

  interfaces = get_wlan_list
  interfaces.each do |interface|
    print "New interface ",interface[:wlan],"\n"
    hostapd_procs[interface[:wlan]] = Hostapd_instance.new(interface[:wlan])
  end
  wlanbridge_proc = Wlanbridge_instance.new()
  radiusclient_proc = Radiusclient_instance.new()

  # Get our local MAC and gateway
  controller_ip = get_gateway
  mac = get_mac_address

  radiusclient_proc.set_params(radius_server: controller_ip)

  # time to wait between polls
  wait = DEFAULT_RATE

  # Start by wiping the configeration and pmk file
  clear_ap_config()
  clear_pmk_file()

  # State is "START" unless we don't know our gateway (rXg controller)  yet.
  if controller_ip.nil?
    state = State.new(STATES::WAITGW)
  else
    state = State.new(STATES::START)
  end

  # List of current active interfaces
  interfaces = Array.new

  # Set time for station scan to now
  @next_station_scan = Time.now

  # Failure counter
  response_failures = 0

  # Process Restart Counters for HostAPD, WLANBridge and RadiusClient
  proc_restart_failures = 0

  # Start the state machine
  while @should_run

    # Sleep until next time unless it is a new state
    # TODO: A SYNC from rXg needs to end sleep
    if not state.is_changed
      #puts "No state change recorded"
      state.sleep()
    elsif state.should_sleep
      state.sleep()
    end

    # Update timestamp on pifi.pid for overseerer to make sure this is still running.
    `touch /run/pifi.pid`

    # sleep_secs = state.should_sleep()
    # puts "Kernel.sleep(#{sleep_secs})"
    # if sleep_secs
    #   puts "Kernel.sleep(#{sleep_secs})"
    #   Kernel.sleep(sleep_secs)
    # end

    # The PiFi has started, and is saying hello to rXg
    case state.get

    # Wait for the rXg gateway address to be available
    # In case Pi starts before rXg
    when STATES::WAITGW
      1.times do
        puts "WAITGW State"
        controller_ip = get_gateway
        if controller_ip.nil?
        # No controller IP yet, wait 10 seconds
          state.set_poll_time(10)
          puts "Waiting for Controller IP: #{ controller_ip }"
        else
          state.update(STATES::START)
          puts "Found controller IP: " + controller_ip
        end
      end # end of 1.times do

    when STATES::START
      1.times do # Loop once, so we can break out if needed.
        puts "START State"
        @start_time = 0
        proc_restart_failures = 0

        result = send_rxg_hello_mesg(controller_ip,mac)
        puts "Reply:",result

        if result.nil? then break end

        wait = process_wait_time(wait,result)


        if result['status'] == 'approved'
          state.update(STATES::CONFIG)
        elsif result['status'] == 'registered' #registered within RXG but not approved. Stay in START state

        else # unknown response status
          puts "Bad HTTP response #{result}  from #{ controller_ip } "
          break
        end

        poll_timer = result["poll_timer"]
        puts "setting poll timer to #{poll_timer} secs."
        state.set_poll_time(poll_timer)
      end # end of 1.times do

    # The PiFi is asking for a configuration
    # The PiFi will send the hostapd.conf hashes and the pmk_hash.
    # The rXg should return all the configs.
    # This will only apply the configs if they have changed.
    when STATES::CONFIG

      1.times do # Loop once, so we can break out if needed.
        puts "CONFIG state"
        @start_time = 0
        static_vids = {}
        result = send_rxg_conf_mesg(controller_ip,mac,config_hashes,pmk_hash)
        wait = process_wait_time(wait, result)

        if result.nil?
          response_failures += 1
          puts "nothing returns from rXg, retries: #{ response_failures }"
          if response_failures > RXG_RETRIES
            puts "#{ RXG_RETRIES } falures, disabling PiFi"
            state.update(STATES::DISABLING)
            response_failures = 0
          end
          break
        end

        status = result["status"]
        if (status != "success")
          puts "config response status '#{status}'. Putting PIFI into Disabling state"
          state.update(STATES::DISABLING)
          break
        end


        # set radius secret
        if !result["radius_secret"].nil?

          puts "@@@@ Setting Radius Secret: " + result["radius_secret"]
          radiusclient_proc.set_params(radius_secret: result["radius_secret"])
        end


        pmk = result["pmk"]

        new_pmk = false
        # optionally write a new pmk file
        if ((not pmk.nil?) and (pmk_hash != result["pmk_hash"]))
          pmk_hash = result["pmk_hash"]
          write_pmk(pmk_hash,pmk)
          new_pmk = true
          puts "*** New PMK File"
        end

        active_interfaces = Array.new
        devices = result["radios"]
        print "DEVICES: ",devices,"\n"
        interface_change = false
        # Go through interfaces
        # Write a new hostapd.wlanX.conf file for each config where the hash differs,
        # Start AP for new configs
        # Restart AP if config changed
        # Stop device if no longer enabled.
        hostapd_procs.each do | interface , hostapd_proc |
          # Find a matching wlan for this proc
          device=devices.select{|x| x["wlan"] == interface}.first
          if not device.nil?
            if not device["wlan"].nil? and not device["config"].nil?
              config_hash = device["config_hash"]
              wlan = device["wlan"]
              mode = device["config"]["mode"]
              config = device["config"]
              # If the mode is "AP" we need to set up this interface.  First check the config_hash for a change
              if mode == "AP"
                print "FOUND AP:",wlan,"\n"
                ap_config=config["hostapd"]
                active_interfaces.push(wlan)
                if config_hashes[wlan] != config_hash
                  interface_change = true
                  static_vid, ssid, chan =write_config(config_hash,ap_config,hostapd_procs)
                  # Save channel to report to rXg
                  @channels[interface] = chan
                  # If static vid in config, use that
                  if static_vid > 0
                    static_vids[wlan] = {static_vid: static_vid, ssid: ssid}
                    puts "VIDS[#{ssid}]:",static_vids
                  end
                  config_hashes[wlan] = config_hash
                  print "*** New Config for ",wlan,"\n"
                  if hostapd_proc.is_running
                    hostapd_proc.stop()
                  end
                  sleep(2)
                  #hostapd_proc.run_or_hup(WLAN_STATES::AP)
                  hostapd_proc.set_to_start
                elsif new_pmk
                  # If the pmks change, we must reload
                  puts "reloading pmks for #{ wlan }"
                  cmd = "hostapd_cli -i #{ wlan } reload_wpa_psk"
                  result = `#{cmd}`.chomp
                  if result != "OK"
                    puts "Reload pmks failed, restarting hostapd for #{ wlan }"
                    #hostapd_proc.run_or_hup(WLAN_STATES::AP)
                    hostapd_proc.set_to_start
                  end
                else
                  print "Not a NEW Config for ",wlan,"\n"
                end
              elsif mode == "OFF"
                if config_hashes[wlan] != config_hash
                  config_hashes[wlan] = config_hash
                  print "Stop: ",interface,"\n"
                  interface_change = true
                  if hostapd_proc.is_running
                    hostapd_proc.stop()
                  end
                end
              else
                print "Unknown radio mode: ",mode,"\n"
              end
            end
          end
        end
        # Restart wlanbridge if an interface changed
        if interface_change or not wlanbridge_proc.is_running
          print "INTERFACE CHANGE!","\n"
          wlanbridge_proc.stop()
          sleep(1)
          wlanbridge_proc.run(active_interfaces,static_vids)
        end

        # Start Radius Client
        if !radiusclient_proc.is_running
          radiusclient_proc.run()
        end
        @start_time = Time.now
        state.update(STATES::RUN)

        # Start the hostaps
        hostapd_procs.each do | interface , hostapd_proc |
          #puts "START HOSTAPD: #{interface}:#{hostapd_proc.state}"
          if hostapd_proc.state == WLAN_STATES::WAIT_AP
            hostapd_proc.run_or_hup(WLAN_STATES::AP)
          end
        end
        
      end # end of 1.times do

    # The PiFi is in a misconfigured state
    when STATES::HEALTH
      puts "HEALTH State"

    # The PiFi is up and running
    when STATES::RUN
      1.times do # Loop once, so we can break out if needed.
        puts "RUN State"

        if proc_restart_failures >= PROC_RESTART_RETRIES
          puts "Excessive ProcRestartFailures: #{proc_restart_failures}."
          state.update(STATES::DISABLING)
          break
        end

        hostapd_procs.each do | interface ,  hostapd_proc |
          if hostapd_proc.state == WLAN_STATES::AP
            if not hostapd_proc.is_running
              print "hostapd for ", hostapd_proc.wlan," has unexpectedly stopped","\n"
              state.update(STATES::DISABLING)
              break
            end
          end
        end
        if state.get != STATES::RUN # HostAPD instance has crashed, break out of RUN case.
          break
        end

        if not wlanbridge_proc.is_running
          puts "wlanbridge has unexpectedly stopped"
          state.update(STATES::DISABLING)
          break
        end

        if not radiusclient_proc.is_running
          puts "Radius Client has unexpectedly stopped. Restarting."
          radiusclient_proc.run()
          proc_restart_failures += 1
          break
        end

        # Reset counter
        proc_restart_failures = 0

        # See if time for next station scan
        if Time.now > @next_station_scan
          @interfaces = hostapd_procs.keys
          @stations = gather_station_info(@channels,@connection_states,hostapd_procs)
          @station_report = {"AP" => mac, "Stations" => @stations}
          puts "####################### Stations ###########################"
          puts @station_report.to_json
          result = send_rxg_clients_mesg(controller_ip,@station_report)
          puts "Send stations result: #{ result }"
          @next_station_scan = Time.now + STATION_SCAN_TIME
        end

        @uptime = Time.now - @start_time
        result = send_rxg_alive_mesg(controller_ip,mac,config_hashes,pmk_hash,@channels,@uptime)
        puts "Alive result:",result
        if result.nil?
          response_failures += 1
          puts "nothing returns from rXg, retries: #{ response_failures }"
          if response_failures > RXG_RETRIES
            puts "#{ RXG_RETRIES } falures, disabling PiFi"
            state.update(STATES::DISABLING)
            response_failures = 0
          end

        elsif (result["status"] == "success") #nothing needed to be performed

        elsif (result["status"] == "update") #we need to switch back to get a new config as we are out of date
          puts "Received update to alive message. Switching to CONFIG state"
          state.update(STATES::CONFIG)
        elsif (result["status"] == "fail") #AP has most likely been disabled.
          puts "Received FAIL to alive message. Disabling Radio"
          state.update(STATES::DISABLING)
        else #unknown state? what to do here?
        end
      end # end of 1.times do

     #This state disables hostapd
    when STATES::DISABLING
      puts "Disabling hostapd, wlanbridge and radius_client"
      hostapd_procs.each do | interface, hostapd_proc |
        if hostapd_proc.is_running
          hostapd_proc.stop()
        end
      end

      if wlanbridge_proc.is_running
        wlanbridge_proc.stop()
      end

      if radiusclient_proc.is_running
        radiusclient_proc.stop()
      end

      clear_ap_config()
      clear_pmk_file()

      # Invalidate config/PMK hashes
      config_hash = "FFFFFFFFFFFF"
      pmk_hash = "FFFFFFFFFFFF"

      #set back to 30 seconds and force pause
      state.set_poll_time(30)
      state.update(STATES::START,true)
    end
  end # End of State Machine Loop

  # Cleanup
  hostapd_procs.each do | interface , hostapd_proc |
    print "Stopping hostapd on ",interface,"\n"
    hostapd_proc.stop()
  end
  wlanbridge_proc.stop()
  radiusclient_proc.stop()

  #response = Client.get(mesg)
  #puts response
end
###################################################################################################
###################################################################################################
# Main program entry point
###################################################################################################
###################################################################################################
# Write out our pid for the systemd
mypid=$$
print "My PID:",mypid,"\n"
File.open("/run/pifi.pid", "w") { |f| f.write mypid,"\n" }

#see if any other instances of pifi are running
lockfile = File.new("/tmp/pifi_controller.lock", "w")
ret = lockfile.flock( File::LOCK_NB | File::LOCK_EX )
if (ret === false)
  puts "Another instance of pifi controller is running. Exiting"
  exit -1
end

#catch ctrl+c and terminates hostapd and wlanbridge
trap("INT") {
  puts "CTRL+C Caught, stopping pifi_state_machine"
  @should_run = false
}

# Enable Logging
logging_directory = '/var/log/pifi'
FileUtils.mkdir_p logging_directory
# creates up to 10, 10 MB log files
$logger = Logger.new(logging_directory + "/pifi.log", 10, 10 * 1024 * 1024)

$logger.info{"PIFI STATE MACHINE Version #{MAJOR}.#{MINOR}.#{REVISION}"}
$logger.info{"Running Directory: '#{__dir__}/'."}

# Main running loop. In case exception occurrs, log it and continue.
# CTRL+C Trap toggles should_run
while @should_run
  begin
    pifi_management()
  rescue Interrupt => e
    puts "Exiting via Interrupt"
    break
  rescue SystemExit => e
    puts "Exiting via SystemExit"
    break
  rescue Exception => exception
    puts "pifi_management threw error: " + exception.inspect
    puts "Backtrace: " + exception.backtrace.inspect
  end
  sleep(1)
end

# Close to flush any remaining log entries
$logger.close()
