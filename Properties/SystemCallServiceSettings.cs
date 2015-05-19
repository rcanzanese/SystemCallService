/* Copyright 2015 Ray Canzanese
 * email:  rcanzanese@gmail.com
 * url:    www.canzanese.com 
 *
 * This file is part of SystemCallService.
 *
 * SystemCallService is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * SystemCallService is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SystemCallService.  If not, see <http://www.gnu.org/licenses/>.
 */


using System.ComponentModel;
using System.Configuration;

namespace SystemCallService.Properties {
    
    
    // This class allows you to handle specific events on the settings class:
    //  The SettingChanging event is raised before a setting's value is changed.
    //  The PropertyChanged event is raised after a setting's value is changed.
    //  The SettingsLoaded event is raised after the setting values are loaded.
    //  The SettingsSaving event is raised before the setting values are saved.
    internal sealed partial class SystemCallServiceSettings {
        private void SettingChangingEventHandler(object sender, SettingChangingEventArgs e) {
            // Add code to handle the SettingChangingEvent event here.
        }
        
        private void SettingsSavingEventHandler(object sender, CancelEventArgs e) {
            // Add code to handle the SettingsSaving event here.
        }
    }
}
