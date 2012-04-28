require 'yaml'
require 'resolv'
require 'rubygems'
require 'net/ssh'
require 'net/scp'
require 'yaml'
require 'ipaddr'
require 'ping'

@user          = "root"
@repo          = "http://mirror.sac1.zdsys.com/ubuntu/"
@debug         = true
@postout       = ""

@args_def =
  {
  :autoboot   => "Should a VM autoboot on a host system reboot values 'true' or 'false'",
  :cpus       => "Number of virtual cpus to assign to the vm. You can overcommit.",
  :localfile  => "The local file location you wish to upload",
  :remotefile => "The name and location of the destination file",
  :file       => "Source file to import",
  :ip         => "The ipaddress for this VM to use. Use also to calculate the mac address",
  :iso        => "Enter the full name of the iso. hint: rake list-isos <filter>",
  :mem        => "Total mem in GB to assign to the vm",
  :mac        => "The mac address for the new VM. This should correspond to the master list so that the vm can get the proper ip from dhcp",
  :name       => "New VM Name (e.g. app66)",
  :partsize   => "The size of the root partition in GB", 
  :pod        => "Name of the pod",
  :template   => "Name of the template. Run 'rake tmplist filter=linbsd' to see the custom templates",
  :xenhost    => "XenServer hostname or ipaddress"
}

@config = YAML.load(File.open("#{File.dirname(__FILE__)}/xen.yml"))

task :default do
  puts `rake --tasks`
end

def get_dna_dir pod
  "#{File.dirname(__FILE__)}/../pods/#{pod}"
end

def get_dna_name pod, name
  "#{get_dna_dir pod}/#{name}.yaml"
end

def generate_dna name, pod, ip
  dna = ""
  perror "Dna already exists for #{name} in #{pod}!" if File.exists?("get_dna_name pod, name}")
  File.mkdir(get_dna_dir(pod)) unless File.directory?(get_dna_dir(pod))
  dna = File.open(get_dna_name(pod,name),"w+")
  dna.puts "---\nrun_list:\n- role[xen]\ncommon_ip: #{ip}\nhostname: #{name}.#{pod}.zdsys.com\n"
  dna.close
  @postout << "\nDna files have been created for #{pod} and need to be commited to git!"  
  nil
end

def ensure_args args
  out = ""
  args << :xenhost #unless ENV['podname']
  args << :pod
  args.uniq.map { |a| out << "\n\t #{a}=<#{a}> #{@args_def[a].to_s}" unless ENV[a.to_s]  }
  perror "\nArguments required: #{out}" unless out.empty?
end

def host_pingable? ip
  Ping.pingecho(ip, 10)
end

def ip_found_in_pod_yml? pod, ip
  podhash = read_yaml_file "#{File.dirname(__FILE__)}/../config/pod/#{pod}.yaml"
  podhash.find{|k,v| v['common_ip'] == "#{ip}" } ? true : false
end

def ip_found_in_dna? pod, ip
  found = nil
  # Check pod config yaml first. 
  found = ip_found_in_pod_yml? pod, ip
  # Then check our new dna in case this was already used but not yet processed
  walk_dna(pod) do |hash,results|
    if ip == hash["common_ip"]
      found = true
      @postout << "The ip was found in #{hash[:node]} "
    end
  end
  found
end

desc "Find if an ip appears in dna"
task :ip_in_dna do
  ensure_args [ :ip ]
  puts ip_found_in_dna?(ENV['pod'],ENV['ip'])
end

def ip_in_range? min, max, ip
  (ip < max && ip > min)
end

def validate_ip pod, xenhost, ip
  min = IPAddr.new("#{@config[pod][xenhost[/\w+/,0]]['ip_min']}")
  max = IPAddr.new("#{@config[pod][xenhost[/\w+/,0]]['ip_max']}")
  ip = IPAddr.new(ip)
  perror "Invalid pod:#{pod}. Not found in xen.yml" unless @config[pod]
  perror "The ipaddress:#{ip} is outside the valid ip range min:#{min}, max:#{max}" unless ip_in_range? min, max, ip
  perror "The ipaddress:#{ip} is apparantly already in use! Ping returned a response" if host_pingable?ip
  perror "The ipaddress:#{ip} was located in dna!" if ip_found_in_dna?(pod,ip)
end

desc "Validate IP"
task :validateip do
  ensure_args [ :pod, :xenhost, :ip ]
  validate_ip ENV['pod'], ENV['xenhost'], ENV['ip']
end

def process_config &block
  @config[pod].each do |h|
    yield(hash,results)
  end
end

def find_hyper pod
  vm_count = {}
  perror "Invalid pod:#{pod}. Not found in xen.yml" unless @config[pod]
  @config[pod].each do |h|
    xenhost = "#{h[0]}.#{pod}"
    vm_count[h[0]] = list_vms.size.to_s
  end
  "#{vm_count.sort_by {|k,v| v.min }.first.first}.#{pod}"
end

desc "find most free hypervisor"
task :get_hyper do
  ensure_args [ :pod ]
  puts find_hyper ENV['pod']
end

def yesno prompt
  print prompt
  case STDIN.gets.downcase.chomp!
  when "y", "yes"
    return true
  when "n", "no"
    return false
  else
    return false
  end
end

def get_local_pod
  File.open("/etc/podname") {|f| f.read }.chomp
end

def generate_dhcp_inc pod, file
  xen_inc = ""
  walk_dna(pod) do |hash,results|
    ip = 
    xen_inc << create_dhcp_entry(File.basename(hash[:node])[/\w+/,0], pod, hash['common_ip']) if hash['run_list'] and hash['run_list'].include?("role[xen]") and hash['common_ip']
  end
  File.open(file, 'w+'){ |f| f.puts xen_inc }
end

def walk_dna pod=get_local_pod, &block
  results = ""
  phash = read_yaml_file "#{File.dirname(__FILE__)}/../config/pod/#{pod}.yaml"
  Dir["#{File.dirname(__FILE__)}/../pods/#{pod}/*"].each do |node|
    hash = read_yaml_file node
    hash[:node] = node
    hash[:common_ip] = phash["#{node}"]['common_ip'] if phash["#{node}"] && phash["#{node}"]['common_ip'] 
    yield(hash,results)
  end
  results
end

desc "List dhcp servers"
task :getdhcp do
  puts get_node_by_roles "role[dhcp]", get_local_pod
end

def get_node_by_roles role, pod=get_local_pod
  out = []
  walk_dna(pod) do |hash,results|
    out.push((File.basename hash[:node])[/\w+/,0]) if hash['run_list'].include?(role)
  end
  out
end

def read_yaml_file file
  YAML.load(File.open(file).read) 
end

def create_dhcp_entry host, pod, ip
  puts "#{__method__} host:#{host} pod:#{pod} ip:#{ip}"
  "host #{host} {\n\thardware ethernet #{"00:16:3e:%02x:%02x:%02x" % ip.to_s.scan(/\d+/).map(&:to_i).last(3)};\n\tfixed-address #{ip};\n\toption host-name \"#{host}.#{pod}.zdsys.com\";\n\t}\n\n" 
end

desc "Create the dhcp include file for xen instances"
task :gendhcp do
  ensure_args [ :file, :pod ]
  puts generate_dhcp_inc ENV['pod'], ENV['file']
end

def get_network_uuid
  uuid = nil
  uuid = exec_on_dom0("xe network-list bridge=xapi1")[/[\w-]+$/]
  uuid = exec_on_dom0("xe network-list bridge=xapi0")[/[\w-]+$/] unless uuid
  uuid
end

def exec_remotely host, user, cmd
  out = nil
  Net::SSH.start( host, user ) do |ssh|
    out = ssh.exec!(cmd).to_s.strip
  end
  out
end

def copy_to_remote host, user, localfile, remotefile
  Net::SCP.upload!(host,user,localfile,remotefile)
end

def update_dhcpd pod, file
  dhcpdir = "/etc/dhcp3/xen"
  @config[pod]["dhcpservers"].each do |s|
    exec_remotely s, "root", "mkdir -p #{dhcpdir}"
    copy_to_remote s, "root", file, "#{dhcpdir}/#{File.basename(file)}"
    exec_remotely s, "root", "service dhcp3-server restart"
  end
  ""
end

desc "Update dhcpd"
task :update_dhcp do
  ensure_args [ :pod, :file ]
  puts update_dhcpd ENV['pod'], ENV['file']
end

def exec_on_dom0 cmd
  exec_remotely ENV['xenhost'], "root", cmd
end

def does_vm_exist? name
  get_uuid_by_vmname(name).empty? ? false : true 
end

def get_vnc_port name
  check_vm_exists name  
  exec_on_dom0("xenstore-ls /local/domain/$(xe vm-param-get uuid=#{get_uuid_by_vmname(name)} param-name=dom-id)").grep(/vnc-port/).first[/(\w+)\"$/, 1]
end

desc "get_vnc_port"
task :getvnc do
  ensure_args [ :name ]
  puts get_vnc_port ENV['name']
end

def get_uuid_by_vmname name 
  exec_on_dom0 "xe vm-list name-label=#{name}|awk '($0 ~ \"^uuid\") {print $NF}'"
end

def get_uuid_by_tmpname name 
  exec_on_dom0 "xe template-list name-label=#{name}|awk '($0 ~ \"^uuid\") {print $NF}'"
end

def filter_results output, filter
  output = output.split("\n\n").select { |l| l.match(Regexp.escape(filter)) } if filter
  output
end

def filter_results_inverse output, filter
  output = output.split("\n\n").select { |l| !l.match(filter) } if filter
  output
end

def list_vms filter=nil
  filter_results exec_on_dom0("xe vm-list  is-control-domain=false"), filter
end

def perror msg 
  puts "Error: #{msg}"
  exit 2
end

def valid_uuid uuid
  /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/.match uuid
end

def bind_default_nic name, mac
  check_vm_exists name
  exec_on_dom0 "xe vif-create mac=#{mac} network-uuid=#{get_network_uuid} vm-uuid=#{get_uuid_by_vmname name} device=0"
end

def get_vif_uuid_by_vm name
  check_vm_exists name
  uuid =  exec_on_dom0("xe vif-list vm-uuid=#{get_uuid_by_vmname name}").grep(/^uuid/)
  if uuid.to_s.empty?
    nil
  else
    uuid[0][/[\w-]+$/]
  end
end

def delete_vif_by_uuid uuid
  valid_uuid uuid
  exec_on_dom0 "xe vif-destroy uuid=#{uuid}"
end

def set_install_repo name, url
  exec_on_dom0 "xe vm-param-set uuid=#{get_uuid_by_vmname name} other-config:install-repository=#{url}"
end

def set_autoboot name,autoboot 
  exec_on_dom0 "xe vm-param-set uuid=#{get_uuid_by_vmname name} other-config:auto_poweron=#{autoboot ? 1 : 0}"
end

desc "Set autoboot on a VM"
task :autobootset do
  ensure_args [ :name, :autoboot ]
  set_autoboot ENV['name'], ENV['autoboot']
end

def set_cpus name,cpus
  puts "#{__method__} name:#{name} cpus:#{cpus}"
  exec_on_dom0 "xe vm-param-set uuid=#{get_uuid_by_vmname name} VCPUs-max=#{cpus}"
  exec_on_dom0 "xe vm-param-set uuid=#{get_uuid_by_vmname name} VCPUs-at-startup=#{cpus}"
end

def set_mem name, mem
  exec_on_dom0 "xe vm-memory-limits-set uuid=#{get_uuid_by_vmname name} static-min=#{mem}GiB dynamic-min=#{mem}GiB dynamic-max=#{mem}GiB static-max=#{mem}GiB"
end

def convert_vm_to_template name, is_tmp
  exec_on_dom0 "xe vm-param-set is-a-template=#{is_tmp} uuid=#{get_uuid_by_vmname name}"
end

desc "Convert VM to template, or Template to vm"
task :set2tmp do
  ensure_args [ :name, :is_tmp ]
  convert_vm_to_template ENV['name'], ENV['is_tmp']
end

desc "Convert Template to VM"
task :tmp2vm do
  ensure_args [ :name ]
  convert_vm_to_template ENV['name']
end


def get_mac_from_ip ip
  "00:16:3e:%02x:%02x:%02x" % "#{ip}".scan(/\d+/).last(3).map(&:to_i)
end

def list_vdi_for_vm name, filter=nil
  filter_results exec_on_dom0("xe vbd-list vm-uuid=#{get_uuid_by_vmname name}"), filter
end

def delete_all_vdi_by_vm name
  perror "VM #{name} is currently running. Please run 'rake shutdown name=#{name}' before nuking it's disk." if is_vm_running?name
  filter_results_inverse(list_vdi_for_vm(name),": xvdd").each do |v|
    delete_vdi v.grep(/vdi-uuid/)[0][/[\w-]+$/]
  end
end

desc "nuke disks"
task :nukedisk do
  ensure_args [ :name ]
  puts delete_all_vdi_by_vm ENV['name']
end

def delete_vdi uuid
  puts exec_on_dom0 "xe vdi-destroy uuid=#{uuid}"
end

def is_vm_running? name
  exec_on_dom0("xe vm-list uuid=#{get_uuid_by_vmname name}")[/power-state (.*): (.*)/,2] == "running" ? true : false
end

def vm_param_list name
  ensure_args [ :name ]
  exec_on_dom0 "xe vm-param-list uuid=#{get_uuid_by_vmname name}"
end

def check_vm_exists name
  unless @vm_exists 
    perror "VM #{name} does not exist" unless does_vm_exist? name
    @vm_exists = true
  end
end

def shutdown name
  check_vm_exists name
  exec_on_dom0 "xe vm-shutdown force=true vm=#{name}" if is_vm_running?name
end

def startup_vm name
  check_vm_exists name
  perror "VM is already running" if is_vm_running?name
  exec_on_dom0 "xe vm-start vm=#{name}"
end

def destroy_vm name, pod
  puts "#{__method__} #{name}"
  check_vm_exists name
  shutdown name
  delete_all_vdi_by_vm name
  exec_on_dom0 "xe vm-destroy uuid=#{get_uuid_by_vmname name}"
  File.delete get_dna_name(pod,name) if File.exist? get_dna_name(pod,name)
  @postout << "VMs were removed and we have deleted their dna. Please commit pods/"
end

def list_templates filter="linbsd"
  filter_results exec_on_dom0("xe template-list"), filter
end

def template_exist? template
  list_templates(template).empty? ? false : true
end

def add_root_dev name, size
  exec_on_dom0 "xe vm-disk-add uuid=#{get_uuid_by_vmname name} disk-size=#{size}GiB device=0"
end

def list_isos filter=nil
  filter_results exec_on_dom0("xe vdi-list"), filter
end

desc "List Available ISOs: optional filter=<filter>"
task :listiso do
  puts list_isos ENV['filter']
end

def get_uuid_cd_drive 
  filter_results(exec_on_dom0("xe cd-list"), "SCSI").to_s.split(": ")[1].first 
end

def attach_iso_to_vm name, iso
  exec_on_dom0 "xe vm-cd-add cd-name=#{iso} vm=#{name} device=3"
end

desc "get cd drive"
task :getcd do
  ensure_args []
  puts get_uuid_cd_drive 
end

desc "Delete a VM"
task :vmdelete do
  ensure_args [ :name, :pod ]
  exit unless yesno("Are you sure you wish to delete the VM #{ENV['name']}? <y/n> ")
  puts destroy_vm ENV['name'], ENV['pod']
  puts "> Removing from rna"
  puts %x{ bin/remove-opsdb #{ENV['pod']} #{ENV['name']} }
end

desc "List Templates. optional: filter=<filter>"
task :tmplist do
  ensure_args [ ]
  puts list_templates ENV['filter'] 
end

desc "Post Installation task"
task :postinstall do
  ensure_args [ :name ]
  shutdown ENV['name']
  convert_vm_to_template ENV['name'], true
end

desc "get network uuid"
task :get_network_uuid do
  ensure_args [ ]
  puts get_network_uuid
end

desc "Get console port"
task :get_console do
  ensure_args [ :name ]
  puts get_vnc_port ENV['name']
end

desc "List running VMs. Optional: filter=<filter> argument"
task :vmlist do
  ensure_args [ ]
  puts list_vms ENV['filter']
end

desc "Set number of VCPUs for VM"
task :cpuset do
  ensure_args [ :name, :cpus ]
  set_cpus ENV['name'],ENV['cpus']
end

desc "Bind nic to vm as default"
task :bind_default_nic do
  ensure_args [ :name, :mac ]
  puts bind_default_nic ENV['name'],ENV['mac']
end

desc "Set total mem for the VM in GiB"
task :memset do
  ensure_args [ :name, :mem ]
  set_mem ENV['name'],ENV['mem']
end

desc "Create template VM instance"
task :tmpnew do
  ensure_args [ :name, :mem, :cpus, :partsize, :template, :ip  ]
  perror "A VM named #{ENV['name']} already exists. Pick another name or destroy the first one"  if does_vm_exist? ENV['name']
  autoboot = ENV['autoboot'] ? ENV['autoboot'] : false
  uuid = exec_on_dom0 "xe vm-install template=\"#{ENV['template']}\" new-name-label=#{ENV['name']}"
  perror "Invalid uuid returned from vm-install. value: #{uuid}" unless valid_uuid uuid
  puts bind_default_nic ENV['name'], ENV['mac']
  puts "Set the default mirror for distro."
  puts set_install_repo ENV['name'], @repo
  puts "Setup autoboot. (should the vm start automatically?)"
  puts set_autoboot ENV['name'], autoboot
  puts "Set CPU count for this VM"
  puts set_cpus ENV['name'], ENV['cpus']
  puts "Set Mem for this VM"
  puts set_mem ENV['name'], ENV['mem']
  puts "Setup the root partition"
  add_root_dev ENV['name'], ENV['partsize']
  # puts "Inserting iso to cd drive"
  # puts attach_iso_to_vm ENV['name'], ENV['iso']
  puts "Start the vm up"
  puts startup_vm ENV['name']
  puts "\nYou can use TightVNC or equivalent to connect to #{ENV['name']}"
  puts "vncviewer -via root@#{ENV['xenhost']} localhost:#{get_vnc_port ENV['name']}"
  puts "Walk through the installation of what is required."
  puts "When complete run 'rake postinstall name=#{name=ENV['name']}'"
end

desc "Create a new vm from a template"
task :vmnew do
  ensure_args [ :name, :template, :ip, :pod ]
  perror "Template #{ENV['template']} does not exist." unless template_exist?ENV['template']
  perror "A VM named #{ENV['name']} already exists. Pick another name or destroy the first one"  if does_vm_exist? ENV['name']

  validate_ip ENV['pod'], ENV['xenhost'], ENV['ip']
  generate_dna ENV['name'], ENV['pod'], ENV['ip']

  puts "> Generate new dhcp include file"
  puts generate_dhcp_inc ENV['pod'], "/tmp/#{ENV['pod']}.include"

  puts "> Update dhcp servers"
  update_dhcpd ENV['pod'], "/tmp/#{ENV['pod']}.include"
  uuid = exec_on_dom0 "xe vm-install template=\"#{ENV['template']}\" new-name-label=#{ENV['name']}"
  perror "Invalid uuid returned from vm-install. value: #{uuid}" unless valid_uuid(uuid)

  puts "> Set the default mirror for distro."
  puts set_install_repo ENV['name'], @repo

  puts "> Removing template nic"
  puts delete_vif_by_uuid get_vif_uuid_by_vm(ENV['name'])

  puts "> Creating default nic with proper mac bound to bind0"
  puts bind_default_nic ENV['name'], get_mac_from_ip(ENV['ip'])

  puts "> Starting up the VM"
  puts startup_vm ENV['name']

  puts "> Convert dhcp to static"
  sleep(10) # Ensure the vm has time to boot
  copy_to_remote ENV['ip'], "root", "#{File.dirname(__FILE__)}/../bin/convert-dhcp-static", "/tmp/convert-dhcp-static"
  exec_remotely ENV['ip'], "root", "/tmp/convert-dhcp-static"
  puts "> Calling create-baremetal-helper"
  puts "\nYou can use TightVNC or equivalent to connect to #{ENV['name']}"
  puts "vncviewer -via root@#{ENV['xenhost']} localhost:#{get_vnc_port ENV['name']}"
end

desc "List all VDi's assigned to a vm: optional filter=<filter>"
task :vidslist do
  ensure_args [ :name ]
  puts list_vdi_for_vm ENV['name'], ENV['filter']
end

task :is_vm_running do
  ensure_args [ :name ]
  puts is_vm_running? ENV['name']
end

desc "List all settings for a VM"
task :explain do
  ensure_args [ :name ]
  check_vm_exists ENV['name']
  puts vm_param_list ENV['name']
end

desc "Template post installation steps"
task :post_install do
  ensure_args [ :name ]
  check_vm_exists name
  shutdown ENV['name']
  convert_vm_to_template ENV['name'], true
end

desc "Shutdown a VM"
task :shutdown do
  ensure_args [ :name ]
  puts shutdown ENV['name']
end

desc "Startup a VM"
task :start do
  ensure_args [ :name ]
  puts startup_vm ENV['name']
  ssh end

desc "Export a template"
task :tmpexport do
  ensure_args [ :name, :dest ]
  perror "Template #{ENV['name']} does not exist" unless template_exist?ENV['name']
  exec_on_dom0 "xe template-export filename=#{ENV['dest']} template-uuid=#{get_uuid_by_tmpname(ENV['name'])}"
end

desc "Import a template"
task :tmpimport do
  ensure_args [ :file ]
  exec_on_dom0 "xe vm-import filename=#{ENV['file']} "
end

desc "Snapshot a VM"
task :vmsnapshot do
  ensure_args [ :name ]
  exec_on_dom0 "xe vm-snapshot uuid=#{get_uuid_by_vmname(ENV['name'])} new-name-label=#{ENV['name']}.#{Time.now.to_i}"
end

desc "List Snapshot for a given VM"
task :listsnaps do
  ensure_args [ :name ]
  exec_on_dom0 "xe snapshot-list uuid=#{get_uuid_by_vmname(ENV['name'])}"
end


desc "Remove a template"
task :tmpdelete do
  exit unless yesno("Are you sure you wish to delete the template #{ENV['name']}? <y/n> ")
  ensure_args [ :name ]
  exec_on_dom0 "xe template-uninstall template-uuid=#{get_uuid_by_tmpname(ENV['name'])}"
end

at_exit { puts @postout }
