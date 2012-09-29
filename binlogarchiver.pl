#!/usr/bin/perl
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
#
#			Start List Obj
#
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
{
	package list_obj;
	use Moose;
	use Moose::Util::TypeConstraints;
	
	has Stamp => ( is => 'rw', isa => 'Str', reader => 'get_stamp', writer => 'set_stamp', default => '', );
	has SlaveHost => ( is => 'rw', isa => 'Str', reader => 'get_slavehost', writer => 'set_slavehost', default => '', );
	has BinaryLog => ( is => 'rw', isa => 'Str', reader => 'get_binarylog', writer => 'set_binarylog', default => '', );
	has BinaryPos => ( is => 'rw', isa => 'Str', reader => 'get_binarypos', writer => 'set_binarypos', default => '', );
	has MasterHost => ( is => 'rw', isa => 'Str', reader => 'get_masterhost', writer => 'set_masterhost', default => '', );
	has Message => ( is => 'rw', isa => 'Str', reader => 'get_message', writer => 'set_message', default => '', );
	has reference => ( traits => ['Array'],	is => 'rw', isa => 'ArrayRef[list_obj]', default => sub { [] },	handles => {
			push => 'push',
			splice => 'splice',
		},
	);
}
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
#
#			Start Log Handler
#
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
{
	package log_handler;
	use Moose;
	use Moose::Util::TypeConstraints;
	use base qw(XML::SAX::Base);
	
	my $list = list_obj->new();
	my $tmp_entry = list_obj->new();
	
	sub start_element {
		# print $data->{LocalName}."->".$attribute->{Name}."->".$attribute->{Value};
		my $self = shift;
		my $data = shift;
		
		if ( $data->{LocalName} eq "SlaveSeen" ) {
			foreach my $ak (keys %{ $data->{Attributes} } ) {
				my $attribute = $data->{Attributes}->{$ak};
				if ($attribute->{Name} eq "Stamp" ) {
					$tmp_entry->set_stamp( $attribute->{Value} );
				} elsif ($attribute->{Name} eq "SlaveHost" ) {
					$tmp_entry->set_slavehost($attribute->{Value});
				}
			}

		}
		
		
	}
	
	sub end_element {
	    my ($self, $element) = @_;
		if ( $element->{Name} eq "SlaveSeen") {
			$list->push($tmp_entry);
			$tmp_entry = list_obj->new();
		}
	}
	
	sub return_list () {
		return $list;
	}
	
	
}
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
#
#			Start Slaves
#
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
{
	package slaves; 
	use DBD::mysql;
	use Moose;
	use Moose::Util::TypeConstraints;

	sub get_slaves (\%) {
		
		my %{credentials} = %{$_[1]};

		my @slave_list;
		my $login_query = "show processlist";
		my $login_conf=db_conn->new()->establish(\%credentials);
		my $login_exec = $login_conf->prepare($login_query) or die "Cannot prepare: " . $login_conf->errstr();
		my ($Id, $User, $Host, $db, $Command, $Time, $State, $info );
				
		$login_exec->execute() or die "Cannot execute: " . $login_exec->errstr();
		$login_exec->bind_columns( undef, \$Id, \$User, \$Host, \$db, \$Command, \$Time, \$State, \$info);
		
		while ( $login_exec->fetch() ) {
			my @slave_split = split('\:', $Host);
			push(@slave_list, $slave_split[0]) if ( $Command =~ m/Binlog Dump/ );
		}
		
		return @slave_list;
		
	}
	
	sub get_slave_status (\%\$) {
		
		my %{credentials} = %{$_[1]};
		my $slave_host = ${$_[2]};
		$credentials{'host'} = $slave_host;
		
		my %slave_info;
		
		my ( $Slave_IO_State, $Master_Host, $Master_User, $Master_Port, $Connect_Retry, $Master_Log_File,  
		$Read_Master_Log_Pos, $Relay_Log_File, $Relay_Log_Pos, $Relay_Master_Log_File, $Slave_IO_Running,
		$Slave_SQL_Running, $Replicate_Do_DB, $Replicate_Ignore_DB, $Replicate_Do_Table, $Replicate_Ignore_Table, 
		$Replicate_Wild_Do_Table, $Replicate_Wild_Ignore_Table, $Last_Errno, $Last_Error, $Skip_Counter, 
		$Exec_Master_Log_Pos, $Relay_Log_Space, $Until_Condition, $Until_Log_File, $Until_Log_Pos, $Master_SSL_Allowed,
		$Master_SSL_CA_File, $Master_SSL_CA_Path, $Master_SSL_Cert, $Master_SSL_Cipher, $Master_SSL_Key, $Seconds_Behind_Master);
		
		my $slave_query = "show slave status";
		my $slave_conf=db_conn->new()->establish(\%credentials);
		
		
		my $slave_exec = $slave_conf->prepare($slave_query) or die "Cannot prepare: " . $slave_conf->errstr();
		$slave_exec->execute() or die "Cannot execute: " . $slave_exec->errstr();
		$slave_exec->bind_columns( undef, \$Slave_IO_State, \$Master_Host, \$Master_User, \$Master_Port, \$Connect_Retry, \$Master_Log_File,  
		\$Read_Master_Log_Pos, \$Relay_Log_File, \$Relay_Log_Pos, \$Relay_Master_Log_File, \$Slave_IO_Running,
		\$Slave_SQL_Running, \$Replicate_Do_DB, \$Replicate_Ignore_DB, \$Replicate_Do_Table, \$Replicate_Ignore_Table, 
		\$Replicate_Wild_Do_Table, \$Replicate_Wild_Ignore_Table, \$Last_Errno, \$Last_Error, \$Skip_Counter, 
		\$Exec_Master_Log_Pos, \$Relay_Log_Space, \$Until_Condition, \$Until_Log_File, \$Until_Log_Pos, \$Master_SSL_Allowed,
		\$Master_SSL_CA_File, \$Master_SSL_CA_Path, \$Master_SSL_Cert, \$Master_SSL_Cipher, \$Master_SSL_Key, \$Seconds_Behind_Master);

		while ( $slave_exec->fetch() ) {
			$slave_info{'Slave_IO_State'} = $Slave_IO_State;
			$slave_info{'Master_Host'} = $Master_Host;
			$slave_info{'Seconds_Behind_Master'} = $Seconds_Behind_Master;
			#$slave_info{'Exec_Master_Log_Pos'} = $Exec_Master_Log_Pos;
			$slave_info{'Read_Master_Log_Pos'} = $Read_Master_Log_Pos;  
			$slave_info{'Master_Log_File'} = $Master_Log_File;
			#$slave_info{'Replicate_Wild_Do_Table'} = $Replicate_Wild_Do_Table;
		}
		$slave_exec->finish();
		
		$credentials{'log_message'} = 'NOTICE';
		$credentials{'slave_host'} = $slave_host;
		$credentials{'binary_log'} = $slave_info{'Master_Log_File'};
		$credentials{'binary_pos'} = $slave_info{'Read_Master_Log_Pos'};
		$credentials{'master_host'} = $slave_info{'Master_Host'};
		file_access->new()->update_log(\%credentials);
		
		
		return %slave_info; 
		
	}
	
	sub print_hash (\%) {
		
		my %{print_hash} = %{$_[1]};
		my ($key, $value);

		# unsorted
		#while (($key, $value) = each(%print_hash)){
		#	print $key.", ".$value."\n";
		#}
		
		# sorted desc
		foreach $key (sort keys %print_hash) {
			print "$key: $print_hash{$key}\n";
		}
		
		# Usage
		# slaves->new()->print_hash(\%hash_name);
	}
	
	sub write_slave_status () {
		
	}
	
}
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
#
#			Start Master
#
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
{
	package master;
	use DBD::mysql;
	use Moose;
	use Moose::Util::TypeConstraints;

	sub get_master_info (\%) {
		my %{credentials} = %{$_[1]};
		my %master_info;
		my $master_query = "show master status";
		my $master_conf=db_conn->new()->establish(\%credentials);
		my $master_exec = $master_conf->prepare($master_query) or die "Cannot prepare: " . $master_conf->errstr();
		my ($File, $Position, $Binlog_Do_DB, $Binlog_Ignore_DB);
				
		$master_exec->execute() or die "Cannot execute: " . $master_exec->errstr();
		$master_exec->bind_columns( undef, \$File, \$Position, \$Binlog_Do_DB, \$Binlog_Ignore_DB);
		
		while ( $master_exec->fetch() ) {
			$master_info{'File'} = $File;
			$master_info{'Position'} = $Position;
		}
		
		return %master_info;
	}
	
	sub get_binary_logs (\%) {
		my %{credentials} = %{$_[1]};
		my %binary_logs;
		my $master_query = "show binary logs";
		my $master_conf=db_conn->new()->establish(\%credentials);
		my $master_exec = $master_conf->prepare($master_query) or die "Cannot prepare: " . $master_conf->errstr();
		my ($Log_name, $File_size);
		
		$master_exec->execute() or die "Cannot execute: " . $master_exec->errstr();
		$master_exec->bind_columns( undef, \$Log_name, \$File_size);
		
		while ( $master_exec->fetch() ) {
			$binary_logs{$Log_name} = $File_size;
		}
		
		return %binary_logs;
		
	}
	
	sub get_last_binary_log (\%\%) {
		
		my ( %credentials, %binary_logs, $size, $key, $value, $return_val);
		my $hash_place = 0;
		if ( defined $_[1] and defined $_[2]) {
			%{credentials} = %{$_[1]};
			%{binary_logs} = %{$_[2]};
			
		} elsif (defined $_[1]) {
			%{credentials} = %{$_[1]};
			%binary_logs = master->new()->get_binary_logs(\%credentials);
			
		} else {
			print "ERROR: Requires Credentials\n";
		}
		
		$size = scalar(keys %binary_logs);
		foreach $key (sort keys %binary_logs) {
			$hash_place++;
			if ( $hash_place == $size ) {
				$return_val = $key;
			}
		}
		
		return $return_val;
		
	}
	
	sub purge_binary_logs (\%\@) {

		my %{credentials} = %{$_[1]};
		my @latest_slave_log_list  = @{$_[2]};
		
		#
		# Populate latest_slave_log_list from event log
		#  below is manual example
		#
		push(@latest_slave_log_list, 'mysql-bin.009918');
		
		my $purge_until_log = master->new()->sort_array(\@latest_slave_log_list,'FIRST');
		my $master_conf=db_conn->new()->establish(\%credentials);
		my %binary_log_list = master->get_binary_logs(\%credentials);
				
		if ( master->new()->sort_array(\@latest_slave_log_list,'FIRST') == 
			master->new()->sort_hash(\%binary_log_list,'LAST') ) {

			print "All Slaves on the Latest Master Bin Log, purge till Last\n";
			#$master_conf->do("purge binary logs to '$purge_until_log'");

		} elsif ( master->new()->sort_array(\@latest_slave_log_list,'FIRST') != 
			master->new()->sort_hash(\%binary_log_list,'FIRST') ) {
			
			my $found_log = master->new()->scan_hash(\%binary_log_list,\master->new()->sort_array(\@latest_slave_log_list,'FIRST') );
			if ( $found_log eq "NOTFOUND" ) {

				print "Binary logs mising from master that slave requires\n";
				
			} else {

				print "Purging until $found_log\n";
				
			}
	
		} else {
			
			print "purge binary logs, unexpected error\n";
			
		}

#		print master->new()->sort_array(\@latest_slave_log_list,'FIRST')."<-FIRST SLAVE LOG\n";
#		print master->new()->sort_hash(\%binary_log_list,'FIRST')."<-FIRST BINARY LOG\n";
#		print master->new()->sort_array(\@latest_slave_log_list,'LAST')."<-LAST SLAVE LOG\n";
#		print master->new()->sort_hash(\%binary_log_list,'LAST')."<-LAST BINARY LOG\n";

	}

	sub scan_hash (\%\$) {
		
		my %hash_to_scan = %{$_[1]};
		my $item_to_find = ${$_[2]};
		my @tmp_split; 
		my $return_val = "NOTFOUND";
		
		foreach my $key (sort keys %hash_to_scan) {
				
			@tmp_split = split('\.', $key);
			if ( $tmp_split[1] == $item_to_find) {
				$return_val = $tmp_split[0].$tmp_split[1];
			}
			
		}
		
		return $return_val;
		
	}
	
	sub sort_hash (\%\$) {
		
		my %unsorted_hash = %{$_[1]};
		my $sort_type = $_[2];
		my ($size, $hash_place, $return_val, @item_split);
		$size = scalar(keys %unsorted_hash);
		
		
		if ( $sort_type eq "FIRST") {

			foreach my $key (sort keys %unsorted_hash) {
				$hash_place++;
				if ( $hash_place == 1 ) {
					@item_split = split('\.',$key);
					$return_val = $item_split[1];
				}
			}

		} elsif ( $sort_type eq "LAST") {

			foreach my $key (sort keys %unsorted_hash) {
				$hash_place++;
				if ( $hash_place == $size ) {
					@item_split = split('\.',$key);
					$return_val = $item_split[1];
				}
			}			

		}
		
		return $return_val;
		
	}
	
	sub sort_array (\@\$) {
		#
		# mysql> show binary logs;
		# +------------------+-----------+
		# | Log_name         | File_size |
		# +------------------+-----------+
		# | mysql-bin.009828 | 268435997 |  <- FIRST
		# | mysql-bin.009829 | 140016374 |  <- LAST
		# +------------------+-----------+
		# 2 rows in set (0.07 sec)
		
		my @unsorted_array = @{$_[1]};
		my $sort_type = $_[2];
		my @sorted_array = sort { $a cmp $b } @unsorted_array;
		my ($return_value, @item_split );
		
		if ( $sort_type eq "FIRST" ) {
			@item_split = split( '\.', shift(@sorted_array) );
			$return_value = $item_split[1];
		} elsif ( $sort_type eq "LAST" ) {
			@item_split = split( '\.', pop(@sorted_array) );
			$return_value = $item_split[1];
		} else {
			print "error in sorting logs\n";
		}
		
		return $return_value;
		
	}
	
}

{
	package archive_logs;
	use DBD::mysql;
	use Moose;
	use Moose::Util::TypeConstraints;
	
	
	
}
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
#
#			Start DB Conn
#
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
{
	package db_conn;
	use DBD::mysql;
	use Moose;
	use Moose::Util::TypeConstraints;
	
	sub establish (\%) {
		my %{credentials} = %{$_[1]};
		my $db_connection;
		
		#
		# Use port 3320 as second attempt to connect to slave.  This happens
		# because not all slaves could be on the port in the credentials
		# and there is no way to determine what port the slave is on
		#
		# Replacing this line of code:
		#   my $login_conf = DBI->connect("DBI:mysql:".$credentials{'name'}.":".
		#   $credentials{'host'}.":".$credentials{'port'}, $credentials{'user'},
		#   $credentials{'pass'} );
		#
		eval {                           # try
		     $db_connection = DBI->connect("DBI:mysql:".$credentials{'name'}.":"
		     .$credentials{'host'}.":".$credentials{'port'}, $credentials{'user'},
		     $credentials{'pass'}, {RaiseError => 1, PrintError => 1} ) or die "errconnect";
		};
		if( $@ ) {                       # catch
		     $db_connection = DBI->connect("DBI:mysql:".$credentials{'name'}.":"
		     .$credentials{'host'}.":3320", $credentials{'user'}, $credentials{'pass'})  or die "errconnect";
		}
		
		return $db_connection;
	}
	
}
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
#
#			Start File Access
#
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
{
	package file_access;
	use Moose;
	use Moose::Util::TypeConstraints;
	use base qw(XML::SAX::Base);
	use XML::SAX::ParserFactory;
	use XML::SAX::Writer;
	use XML::Writer;
	use XML::SAX;
	use Encode;
	use IO::File;
	use Tie::File;
	use POSIX qw(strftime);
	use Date::Calc qw (Add_Delta_Days);
	
	
	sub read_log (\%) {
		# retitle to log_access
		
		my %credentials = %{$_[1]};
		my $handler = log_handler->new();
		my $parser_factory = XML::SAX::ParserFactory->parser( Handler => $handler );
		$parser_factory->parse_uri($credentials{'file_path'});
		
		my $smth = $handler->return_list();
		# print $smth;
		# print $smth->reference->{0}->list_obj->get_slavehost();
		
	}
	
	sub update_log (\%) {

		# my %log_hash_sample = (
		#	"log_message" => "NOTICE|ERROR|WARN MESSAGE",
		#	"file_path" => "/home/aguajardo/binloglog.txt",
		#	"slave_host" => "123.123.123.123",
		#	"binary_log" => "mysql-bin.001234",
		#	"binary_pos" => "1000001",
		# );
		
		my %log_hash = %{$_[1]};
		
		
		# check if file exists
		if ( -e $log_hash{'file_path'} ) {
			# continue
		}
		unless ( -e $log_hash{'file_path'}) {
			# write new file if not exists ( the starttag )			
			my $output = new IO::File(">$log_hash{'file_path'}");
			print $output encode('utf8',"<LogFile>\n");	
		}
			
		# remove close tag of file			
		tie my @array, 'Tie::File', $log_hash{'file_path'} or die $!;
		
		if ( $array[$#array] eq "</LogFile>" ) {
			$#array -= 1;
		}
		untie @array;

		# $sftp_user = encode('utf8',$sftp_user)
		
		# start xml writing
		my $output = new IO::File(">>$log_hash{'file_path'}");		
		my $writer = new XML::Writer( DATA_MODE => 'true', DATA_INDENT => 2, OUTPUT => $output );
		my $log_stamp = getThisDayDateTime(0);
		$writer->startTag("SlaveSeen", "Stamp" => $log_stamp, "Message" => $log_hash{'log_message'}, 
		"SlaveHost" => $log_hash{'slave_host'}, "BinaryLog" => $log_hash{'binary_log'},
		"BinaryPos" => $log_hash{'binary_pos'}, "MasterHost" => $log_hash{'master_host'} );

		#$writer->startTag("SlaveSeen", "Stamp" => encode('utf8',$log_stamp) );
		$writer->endTag(encode('utf8',"SlaveSeen"));
		$writer->end();
		print $output encode('utf8',"</LogFile>\n");
		$output->close();
		
	}
	
	sub write_configuration () {
		# $writer->comment("This is the configuration file for EOD processing of unitedtote xml");
	}
	
	sub read_configuration () {
		
	}
	
	sub getDate {
		my @today = localtime;
		return @today;
	}

	sub getThisDayDate {
		#
		# put if statement to check for hash, then set offset as either [0] or [1]
		#
		my ($offset) = $_[1];
		$offset = 0 if(!$offset);
		my @today = &getDate();
		my $date = strftime "%Y %m %d %H:%M:%S", @today;
		my @tmp = split(/\s+/, $date);
		my ($y, $m, $d) = Add_Delta_Days($tmp[0], $tmp[1], $tmp[2], $offset);
		$m = "0".$m if($m<10 and length($m)<2);
		$d = "0".$d if($d<10 and length($d)<2);
		my $thisday = "$y-$m-$d";
		return $thisday;
	}

	sub getThisDayDateTime {
		my ($offset) = @_;
		$offset = 0 if(!$offset);
		my @today = &getDate();
		my $date = strftime "%Y %m %d %H:%M:%S", @today;
		my @tmp = split(/\s+/, $date);
		my ($y, $m, $d) = Add_Delta_Days($tmp[0], $tmp[1], $tmp[2], $offset);
		$m = "0".$m if($m<10 and length($m)<2);
		$d = "0".$d if($d<10 and length($d)<2);
		my $thisday = "$y-$m-$d";
		my $time = strftime " %H:%M:%S", @today;
		return $thisday.$time;
	}
	
}


#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
#
#			Start Main
#
#`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`,`#
{
	package main;
	use DBD::mysql;
	use Moose;
	use Moose::Util::TypeConstraints;

	my %credentials = (
		'user' => 'usea',
		'pass' => 'cunt',
		'name' => 'mysql',
		'host' => '172.17.56.41',
		'port' => '3306',
		'file_path' => '/home/aguajardo/binloglog.txt',
	);
	
	
	my $slave_find = slaves->new();
	my $master_find = master->new();
	my @slave_list = $slave_find->get_slaves(\%credentials);
	my %master_info = $master_find->get_master_info(\%credentials);
	my @latest_slave_log_list;
	
	print $master_find->get_last_binary_log(\%credentials)."\n";
	
	foreach my $slave_host ( @slave_list) {
		my %slave_info = $slave_find->get_slave_status(\%credentials, \$slave_host);
		print $slave_host."\n";
		print "$slave_info{'Read_Master_Log_Pos'} , $master_info{'Position'} - $slave_info{'Master_Log_File'} , $master_info{'File'}\n";
		push (@latest_slave_log_list, $slave_info{'Master_Log_File'});
		
	}
	
	$master_find->purge_binary_logs(\%credentials,\@latest_slave_log_list);
	file_access->new()->read_log(\%credentials);
}



















