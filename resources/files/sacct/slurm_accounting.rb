require 'json'
puts 'start'
puts node['cluster']
puts 'node[cluster] ---^'
puts node['slurm_accounting']
puts 'node[slurm_accounting] ---^'
return if node['cluster']['node_type'] != 'HeadNode'
puts "is head node"

# Get Slurm database credentials
secret = JSON.parse(shell_out!("aws secretsmanager get-secret-value --secret-id #{node['slurm_accounting']['secret_id']} --region #{node['cluster']['region']} --query SecretString --output text").stdout)

puts secret
puts 'got secret...'

case node['platform']
when 'ubuntu'
  package 'mysql-client'
when 'amazon', 'centos'
  package 'mysql'
end


puts 'template1'

template '/tmp/slurm_sacct.conf' do
  source '/tmp/slurm_sacct.conf.erb'
  owner 'root'
  group 'root'
  mode '0600'
  variables(
    slurm_db_user: secret['username'],
    slurm_dbd_host: shell_out!('hostname').stdout.strip
  )
  local true
end

puts 'template2'

template '/tmp/slurmdbd.conf' do
  source '/tmp/slurmdbd.conf.erb'
  owner 'slurm'
  group 'slurm'
  mode '0600'
  variables(
    slurm_db_user: secret['username'],
    slurm_db_password: secret['password'],
    slurm_dbd_host: shell_out!('hostname').stdout.strip
  )
  sensitive true
  local true
end

puts 'service'

file '/etc/systemd/system/slurmdbd.service' do
  owner 'root'
  group 'root'
  mode '0644'
  content ::File.open('/tmp/slurmdbd.service').read
end

service 'slurmdbd' do
  action :start
end

service 'slurmctld' do
  action :restart
end
