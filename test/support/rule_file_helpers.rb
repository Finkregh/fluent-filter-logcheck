# typed: false
# frozen_string_literal: true

require 'tempfile'
require 'fileutils'

# Test helpers for creating and managing rule files
module RuleFileHelpers
  # Create realistic test rule files with various patterns
  def create_real_rule_files(temp_dir)
    create_ignore_rules(temp_dir)
    create_cracking_rules(temp_dir)
    create_violations_rules(temp_dir)
  end

  # Create logcheck directory structure mimicking /etc/logcheck
  def create_logcheck_directory_structure(base_dir)
    directories = %w(
      ignore.d.server
      ignore.d.workstation
      ignore.d.paranoid
      cracking.d
      violations.d
    )

    directories.each do |subdir|
      FileUtils.mkdir_p(File.join(base_dir, subdir))
    end
  end

  # Create ignore rules (messages that should be filtered out)
  def create_ignore_rules(temp_dir)
    ignore_patterns = [
      # Systemd patterns
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: (Started|Stopped) .+\.$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Reached target .+\.$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Listening on .+\.$',

      # Cron patterns
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ cron\[[[:digit:]]+\]: \([[:alnum:]]+\) CMD .*$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ CRON\[[[:digit:]]+\]: \([[:alnum:]]+\) CMD .*$',

      # Kernel patterns
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ kernel: \[[[:space:]]*[[:digit:]]+\.[[:digit:]]+\] .*$'
    ]

    ignore_file = File.join(temp_dir, 'ignore.rules')
    File.write(ignore_file, ignore_patterns.join("\n"))

    # Also create in ignore.d.server structure
    server_dir = File.join(temp_dir, 'ignore.d.server')
    FileUtils.mkdir_p(server_dir)
    File.write(File.join(server_dir, 'systemd'), ignore_patterns[0..2].join("\n"))
    File.write(File.join(server_dir, 'cron'), ignore_patterns[3..4].join("\n"))
    File.write(File.join(server_dir, 'kernel'), ignore_patterns[5].to_s)

    ignore_file
  end

  # Create cracking rules (security alerts)
  def create_cracking_rules(temp_dir)
    cracking_patterns = [
      # SSH attack patterns
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sshd\[[[:digit:]]+\]: Failed password for .* from [.:[:xdigit:]]+ port [[:digit:]]+ ssh2$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sshd\[[[:digit:]]+\]: Invalid user .* from [.:[:xdigit:]]+$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sshd\[[[:digit:]]+\]: ROOT LOGIN REFUSED FROM [.:[:xdigit:]]+$',

      # FTP attack patterns
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ ftpd\[[[:digit:]]+\]: ANONYMOUS FTP LOGIN REFUSED FROM [.:[:xdigit:]]+$',

      # General intrusion patterns
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ .* ATTACK .* FROM [.:[:xdigit:]]+$'
    ]

    cracking_file = File.join(temp_dir, 'cracking.rules')
    File.write(cracking_file, cracking_patterns.join("\n"))

    # Also create in cracking.d structure
    cracking_dir = File.join(temp_dir, 'cracking.d')
    FileUtils.mkdir_p(cracking_dir)
    File.write(File.join(cracking_dir, 'ssh'), cracking_patterns[0..2].join("\n"))
    File.write(File.join(cracking_dir, 'ftp'), cracking_patterns[3].to_s)
    File.write(File.join(cracking_dir, 'general'), cracking_patterns[4].to_s)

    cracking_file
  end

  # Create violations rules (system violations)
  def create_violations_rules(temp_dir)
    violations_patterns = [
      # Disk/hardware errors
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ kernel:.*I/O error.*$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ kernel:.*media error.*bad sector.*$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ kernel:.*temperature above threshold.*$',

      # Security violations
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sudo:.*authentication failure.*$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ su:.*authentication failure.*$'
    ]

    violations_file = File.join(temp_dir, 'violations.rules')
    File.write(violations_file, violations_patterns.join("\n"))

    # Also create in violations.d structure
    violations_dir = File.join(temp_dir, 'violations.d')
    FileUtils.mkdir_p(violations_dir)
    File.write(File.join(violations_dir, 'kernel'), violations_patterns[0..2].join("\n"))
    File.write(File.join(violations_dir, 'auth'), violations_patterns[3..4].join("\n"))

    violations_file
  end

  # Create sample log messages for testing
  def sample_real_log_messages
    {
      # Messages that should be ignored
      systemd_start: 'Dec  8 10:00:00 server systemd[1]: Started nginx.service.',
      systemd_target: 'Dec  8 10:00:00 server systemd[1]: Reached target multi-user.target.',
      systemd_listen: 'Dec  8 10:00:00 server systemd[1]: Listening on SSH daemon socket.',
      cron_job: 'Dec  8 10:00:00 server cron[1234]: (root) CMD (/usr/bin/updatedb)',
      cron_uppercase: 'Dec  8 10:00:00 server CRON[1234]: (user) CMD (echo test)',
      kernel_normal: 'Dec  8 10:00:00 server kernel: [12345.678] Normal kernel message',

      # Messages that should trigger cracking alerts
      ssh_failed: 'Dec  8 10:01:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2',
      ssh_invalid: 'Dec  8 10:01:00 server sshd[1234]: Invalid user hacker from 192.168.1.100',
      ssh_root_refused: 'Dec  8 10:01:00 server sshd[1234]: ROOT LOGIN REFUSED FROM 192.168.1.100',
      ftp_anonymous: 'Dec  8 10:01:00 server ftpd[1234]: ANONYMOUS FTP LOGIN REFUSED FROM 192.168.1.100',
      general_attack: 'Dec  8 10:01:00 server app[1234]: ATTACK detected FROM 192.168.1.100',

      # Messages that should trigger violations alerts
      kernel_io_error: 'Dec  8 10:02:00 server kernel: [12345.678] I/O error, dev sda, sector 12345',
      kernel_bad_sector: 'Dec  8 10:02:00 server kernel: [12345.678] sda: media error (bad sector): status=0x51',
      kernel_temperature: 'Dec  8 10:02:00 server kernel: [12345.678] temperature above threshold, cpu clock throttled',
      sudo_auth_failure: 'Dec  8 10:02:00 server sudo: pam_unix(sudo:auth): authentication failure; logname=user uid=1000',
      su_auth_failure: 'Dec  8 10:02:00 server su: pam_unix(su:auth): authentication failure; logname=user uid=1000',

      # Messages that should pass through (no matching rules)
      normal_app: 'Dec  8 10:03:00 server myapp[5678]: Application started successfully',
      normal_web: 'Dec  8 10:03:00 server nginx[9012]: 192.168.1.50 - - [08/Dec/2024:10:03:00 +0000] "GET / HTTP/1.1" 200',
      normal_db: 'Dec  8 10:03:00 server postgres[3456]: LOG: database system is ready to accept connections'
    }
  end

  # Get expected decision for a message
  def expected_decision_for_message(message_key)
    case message_key
    when :systemd_start, :systemd_target, :systemd_listen, :cron_job, :cron_uppercase, :kernel_normal
      :ignore
    when :ssh_failed, :ssh_invalid, :ssh_root_refused, :ftp_anonymous, :general_attack
      :alert
    when :kernel_io_error, :kernel_bad_sector, :kernel_temperature, :sudo_auth_failure, :su_auth_failure
      :alert
    when :normal_app, :normal_web, :normal_db
      :pass
    else
      :pass
    end
  end

  # Create malformed rule files for error testing
  def create_malformed_rule_files(temp_dir)
    malformed_patterns = [
      '[invalid_regex',      # Unclosed bracket
      '(unclosed_group',     # Unclosed group
      '*invalid_start',      # Invalid quantifier
      '\\invalid_escape',    # Invalid escape sequence
      ''                     # Empty line (should be ignored)
    ]

    malformed_file = File.join(temp_dir, 'malformed.rules')
    File.write(malformed_file, malformed_patterns.join("\n"))
    malformed_file
  end

  # Create large rule file for performance testing
  def create_large_rule_file(temp_dir, rule_count = 1000)
    patterns = []
    rule_count.times do |i|
      patterns << "^test_pattern_#{i}_.*$"
    end

    large_file = File.join(temp_dir, 'large.rules')
    File.write(large_file, patterns.join("\n"))
    large_file
  end

  # Clean up temporary files and directories
  def cleanup_temp_files(*paths)
    paths.each do |path|
      if File.directory?(path)
        FileUtils.rm_rf(path)
      else
        FileUtils.rm_f(path)
      end
    end
  end
end
