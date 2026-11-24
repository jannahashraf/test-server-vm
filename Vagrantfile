VM_NAME = "test-server-vm"
VM_IP = "192.168.56.10"
APP_PORT = 8765

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"
  config.vm.hostname = VM_NAME

  config.vm.network "private_network", ip: VM_IP
  config.vm.network "forwarded_port", guest: APP_PORT, host: APP_PORT, host_ip: "127.0.0.1", auto_correct: true
  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider "virtualbox" do |vb|
    vb.name = VM_NAME
    vb.memory = 2048
    vb.cpus = 2
  end

  config.vm.provision "shell", path: "bootstrap.sh"
end
