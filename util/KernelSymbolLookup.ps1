# Copyright 2015 Ray Canzanese
# email:  rcanzanese@gmail.com
# url:    www.canzanese.com 
#
# This file is part of SystemCallService.
#
# SystemCallService is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SystemCallService is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SystemCallService.  If not, see <http://www.gnu.org/licenses/>.

# Accepts a single command line argument that is the path to a kernel for
# which to lookup the symbols.

# Check for command line argument
if($args.count -lt 1){
	echo "Input the *.binary file output by the SyscallCounterService and get a *.symbol file in return."
	return
} 

# Makes sure the debug tools are in the path.
$env:Path += ";C:\Program Files (x86)\Windows Kits\8.1\bin\x64\"

$inputfile = $args[0];

# Chekc to see if it is a binary file.
if(-not $inputfile -match "\.binary$")
{
	echo "Probably not a binary file.  Make sure you are inputting the binary file SyscallCounterService died on."
	return
}

$outputfile = $inputfile -replace "\.binary$", ".symbols"

dbh.exe $inputfile enum | out-file $outputfile -Encoding ASCII
