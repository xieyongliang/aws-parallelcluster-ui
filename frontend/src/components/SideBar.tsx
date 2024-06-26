// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
// with the License. A copy of the License is located at
//
// http://aws.amazon.com/apache2.0/
//
// or in the "LICENSE.txt" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and
// limitations under the License.
import {
  SideNavigation,
  SideNavigationProps,
} from '@cloudscape-design/components'
import * as React from 'react'
import {useTranslation} from 'react-i18next'
import {useLocation, useNavigate} from 'react-router-dom'
import {AppConfig} from '../app-config/types'
import {getState} from '../store'

export default function SideBar() {
  const {t} = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()

  const activeHref = '/' + location.pathname.split('/')?.[1]

  const header = React.useMemo(
    () => ({
      href: '/clusters',
      text: t('global.menu.header'),
    }),
    [t],
  )

  const navigationItems: ReadonlyArray<SideNavigationProps.Item> =
    React.useMemo(() => {
      return [
        {type: 'link', text: t('global.menu.clusters'), href: '/clusters'},
        {type: 'link', text: t('global.menu.images'), href: '/images'},
        {type: 'link', text: t('global.menu.users'), href: '/users'},
        {type: 'divider'},
        {
          type: 'link',
          text: t('global.menu.viewLicense'),
          href: '/pcui/license.txt',
          external: true,
        },
      ]
    }, [t])

  const navigationItemsNoUsers: ReadonlyArray<SideNavigationProps.Item> =
    React.useMemo(() => {
      return [
        {type: 'link', text: t('global.menu.clusters'), href: '/clusters'},
        {type: 'link', text: t('global.menu.images'), href: '/images'},
        {type: 'divider'},
        {
          type: 'link',
          text: t('global.menu.viewLicense'),
          href: '/pcui/license.txt',
          external: true,
        },
      ]
    }, [t])

  const onFollow = React.useCallback(
    event => {
      if (!event.detail.external) {
        event.preventDefault()
        navigate(event.detail.href)
      }
    },
    [navigate],
  )

  var appConfig: AppConfig = getState(['app', 'appConfig'])
  return (
    <SideNavigation
      header={header}
      activeHref={activeHref}
      onFollow={onFollow}
      items={
        appConfig.authType == 'azuread'
          ? navigationItemsNoUsers
          : navigationItems
      }
    />
  )
}
