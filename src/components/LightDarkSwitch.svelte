<script lang="ts">
import type { LIGHT_DARK_MODE } from '@/types/config.ts'
import { AUTO_MODE, DARK_MODE, LIGHT_MODE } from '@constants/constants.ts'
import I18nKey from '@i18n/i18nKey'
import { i18n } from '@i18n/translation'
import {
  applyThemeToDocument,
  getStoredTheme,
  setTheme,
} from '@utils/setting-utils.ts'
import { onMount } from 'svelte'

const seq: LIGHT_DARK_MODE[] = [LIGHT_MODE, DARK_MODE, AUTO_MODE]
let mode: LIGHT_DARK_MODE = $state(AUTO_MODE)

onMount(() => {
  mode = getStoredTheme()
  const darkModePreference = window.matchMedia('(prefers-color-scheme: dark)')
  const changeThemeWhenSchemeChanged: Parameters<
    typeof darkModePreference.addEventListener<'change'>
  >[1] = e => {
    applyThemeToDocument(mode)
  }
  darkModePreference.addEventListener('change', changeThemeWhenSchemeChanged)
  return () => {
    darkModePreference.removeEventListener(
      'change',
      changeThemeWhenSchemeChanged,
    )
  }
})

function switchScheme(newMode: LIGHT_DARK_MODE) {
  mode = newMode
  setTheme(newMode)
}

function toggleScheme() {
  let i = 0
  for (; i < seq.length; i++) {
    if (seq[i] === mode) {
      break
    }
  }
  switchScheme(seq[(i + 1) % seq.length])
}

function showPanel() {
  const panel = document.querySelector('#light-dark-panel')
  panel.classList.remove('float-panel-closed')
}

function hidePanel() {
  const panel = document.querySelector('#light-dark-panel')
  panel.classList.add('float-panel-closed')
}
</script>

<!-- z-50 make the panel higher than other float panels -->
<div class="relative z-50" onmouseleave={hidePanel}>
    <button aria-label="Light/Dark Mode" aria-haspopup="true" class="relative btn-plain scale-animation rounded-lg h-11 w-11 active:scale-90" id="scheme-switch" onclick={toggleScheme} onmouseenter={showPanel}>
        <div class="absolute" class:opacity-0={mode !== LIGHT_MODE}>
            <svg class="text-[1.25rem]" width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path d="M12 17q-2.075 0-3.537-1.463T7 12q0-2.075 1.463-3.537T12 7q2.075 0 3.538 1.463T17 12q0 2.075-1.462 3.538T12 17zm0-2q1.25 0 2.125-.875T15 12q0-1.25-.875-2.125T12 9q-1.25 0-2.125.875T9 12q0 1.25.875 2.125T12 15zm0 7q-.425 0-.712-.288T11 21v-2q0-.425.288-.712T12 18t.713.288T13 19v2q0 .425-.288.713T12 22zm0-18q-.425 0-.712-.288T11 3V1q0-.425.288-.712T12 0t.713.288T13 1v2q0 .425-.288.713T12 4zm8 9q-.425 0-.712-.288T19 12t.288-.712T20 11h2q.425 0 .713.288T23 12t-.288.713T22 13h-2zM2 13q-.425 0-.712-.288T1 12t.288-.712T2 11h2q.425 0 .713.288T5 12t-.288.713T4 13H2zm16.95 6.55q-.275 0-.525-.112t-.425-.338l-1.4-1.4q-.275-.275-.275-.7t.275-.7t.7-.275t.7.275l1.4 1.4q.3.3.3.713t-.3.687q-.2.25-.45.35t-.5.1zm-13.9-13.9q-.275 0-.525-.112t-.425-.338l-1.4-1.4q-.3-.3-.3-.712t.3-.688q.2-.25.45-.35t.5-.1q.275 0 .525.113t.425.337l1.4 1.4q.275.275.275.7t-.275.7t-.7.275t-.7-.275zm13.9-1.4q-.275-.275-.275-.7t.275-.7l1.4-1.4q.3-.3.713-.3t.687.3q.25.2.35.45t.1.5q0 .275-.112.525t-.338.425l-1.4 1.4q-.275.275-.7.275t-.7-.275zM5.05 19.55q-.275-.275-.275-.7t.275-.7l1.4-1.4q.275-.275.7-.275t.7.275t.275.7t-.275.7l-1.4 1.4q-.3.3-.712.3t-.688-.3z"/></svg>
        </div>
        <div class="absolute" class:opacity-0={mode !== DARK_MODE}>
            <svg class="text-[1.25rem]" width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path d="M12 21q-3.75 0-6.375-2.625T3 12q0-3.75 2.625-6.375T12 3q.35 0 .688.025t.662.075q-1.025.725-1.637 1.888T11.1 7.5q0 2.25 1.575 3.825T16.5 12.9q1.35 0 2.513-.612T20.9 10.65q.05.325.075.663T21 12q0 3.75-2.625 6.375T12 21zm0-2q2.2 0 3.95-1.212T18.3 14.6q-.875.25-1.8.25-3.075 0-5.237-2.163T9.1 7.45q0-.925.25-1.8-2.025.6-3.187 2.35T5 12q0 2.9 2.05 4.95T12 19zm-.25-6.75z"/></svg>
        </div>
        <div class="absolute" class:opacity-0={mode !== AUTO_MODE}>
            <svg class="text-[1.25rem]" width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path d="M12 22q-2.075 0-3.9-.788t-3.175-2.137q-1.35-1.35-2.137-3.175T2 12q0-2.075.788-3.9t2.137-3.175q1.35-1.35 3.175-2.137T12 2q2.075 0 3.9.788t3.175 2.137q1.35 1.35 2.138 3.175T22 12q0 2.075-.788 3.9t-2.137 3.175q-1.35 1.35-3.175 2.138T12 22zm0-2q3.325 0 5.663-2.337T20 12q0-3.325-2.337-5.663T12 4v16z"/></svg>
        </div>
    </button>

    <div id="light-dark-panel" class="hidden lg:block absolute transition float-panel-closed top-11 -right-2 pt-5" >
        <div class="card-base float-panel p-2" role="menu" aria-label="Theme Mode">
            <button role="menuitem" class="flex transition whitespace-nowrap items-center !justify-start w-full btn-plain scale-animation rounded-lg h-9 px-3 font-medium active:scale-95 mb-0.5"
                    class:current-theme-btn={mode === LIGHT_MODE}
                    onclick={() => switchScheme(LIGHT_MODE)}
            >
                <svg class="text-[1.25rem] mr-3" width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path d="M12 17q-2.075 0-3.537-1.463T7 12q0-2.075 1.463-3.537T12 7q2.075 0 3.538 1.463T17 12q0 2.075-1.462 3.538T12 17zm0-2q1.25 0 2.125-.875T15 12q0-1.25-.875-2.125T12 9q-1.25 0-2.125.875T9 12q0 1.25.875 2.125T12 15zm0 7q-.425 0-.712-.288T11 21v-2q0-.425.288-.712T12 18t.713.288T13 19v2q0 .425-.288.713T12 22zm0-18q-.425 0-.712-.288T11 3V1q0-.425.288-.712T12 0t.713.288T13 1v2q0 .425-.288.713T12 4zm8 9q-.425 0-.712-.288T19 12t.288-.712T20 11h2q.425 0 .713.288T23 12t-.288.713T22 13h-2zM2 13q-.425 0-.712-.288T1 12t.288-.712T2 11h2q.425 0 .713.288T5 12t-.288.713T4 13H2zm16.95 6.55q-.275 0-.525-.112t-.425-.338l-1.4-1.4q-.275-.275-.275-.7t.275-.7t.7-.275t.7.275l1.4 1.4q.3.3.3.713t-.3.687q-.2.25-.45.35t-.5.1zm-13.9-13.9q-.275 0-.525-.112t-.425-.338l-1.4-1.4q-.3-.3-.3-.712t.3-.688q.2-.25.45-.35t.5-.1q.275 0 .525.113t.425.337l1.4 1.4q.275.275.275.7t-.275.7t-.7.275t-.7-.275zm13.9-1.4q-.275-.275-.275-.7t.275-.7l1.4-1.4q.3-.3.713-.3t.687.3q.25.2.35.45t.1.5q0 .275-.112.525t-.338.425l-1.4 1.4q-.275.275-.7.275t-.7-.275zM5.05 19.55q-.275-.275-.275-.7t.275-.7l1.4-1.4q.275-.275.7-.275t.7.275t.275.7t-.275.7l-1.4 1.4q-.3.3-.712.3t-.688-.3z"/></svg>
                {i18n(I18nKey.lightMode)}
            </button>
            <button role="menuitem" class="flex transition whitespace-nowrap items-center !justify-start w-full btn-plain scale-animation rounded-lg h-9 px-3 font-medium active:scale-95 mb-0.5"
                    class:current-theme-btn={mode === DARK_MODE}
                    onclick={() => switchScheme(DARK_MODE)}
            >
                <svg class="text-[1.25rem] mr-3" width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path d="M12 21q-3.75 0-6.375-2.625T3 12q0-3.75 2.625-6.375T12 3q.35 0 .688.025t.662.075q-1.025.725-1.637 1.888T11.1 7.5q0 2.25 1.575 3.825T16.5 12.9q1.35 0 2.513-.612T20.9 10.65q.05.325.075.663T21 12q0 3.75-2.625 6.375T12 21zm0-2q2.2 0 3.95-1.212T18.3 14.6q-.875.25-1.8.25-3.075 0-5.237-2.163T9.1 7.45q0-.925.25-1.8-2.025.6-3.187 2.35T5 12q0 2.9 2.05 4.95T12 19zm-.25-6.75z"/></svg>
                {i18n(I18nKey.darkMode)}
            </button>
            <button role="menuitem" class="flex transition whitespace-nowrap items-center !justify-start w-full btn-plain scale-animation rounded-lg h-9 px-3 font-medium active:scale-95"
                    class:current-theme-btn={mode === AUTO_MODE}
                    onclick={() => switchScheme(AUTO_MODE)}
            >
                <svg class="text-[1.25rem] mr-3" width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path d="M12 22q-2.075 0-3.9-.788t-3.175-2.137q-1.35-1.35-2.137-3.175T2 12q0-2.075.788-3.9t2.137-3.175q1.35-1.35 3.175-2.137T12 2q2.075 0 3.9.788t3.175 2.137q1.35 1.35 2.138 3.175T22 12q0 2.075-.788 3.9t-2.137 3.175q-1.35 1.35-3.175 2.138T12 22zm0-2q3.325 0 5.663-2.337T20 12q0-3.325-2.337-5.663T12 4v16z"/></svg>
                {i18n(I18nKey.systemMode)}
            </button>
        </div>
    </div>
</div>
