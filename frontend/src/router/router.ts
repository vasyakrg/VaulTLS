import {createRouter, createWebHistory} from 'vue-router';
import { authGuard } from '@/router/authGuard';

import LoginView from '@/views/LoginView.vue';
import FirstSetupView from '@/views/FirstSetupView.vue';

import MainLayout from '@/layouts/MainLayout.vue';
import OverviewTab from '@/components/OverviewTab.vue';
import SettingsTab from '@/components/SettingsTab.vue';
import UserTab from "@/components/UserTab.vue";
import GroupsTab from "@/components/GroupsTab.vue";
import CATab from "@/components/CATab.vue";
import AcmeTab from '@/components/AcmeTab.vue';
import AcmeClientTab from '@/components/AcmeClientTab.vue';
import AuditTab from '@/components/AuditTab.vue';
import ProfileTab from '@/components/ProfileTab.vue';

const router = createRouter({
    history: createWebHistory(),
    routes: [
        {
            path: '/login',
            name: 'Login',
            component: LoginView,
            meta: { public: true },
        },
        {
            path: '/first-setup',
            name: 'FirstSetup',
            component: FirstSetupView,
            meta: { public: true },
        },
        {
            path: '/',
            component: MainLayout,
            // Child routes for the main app
            children: [
                {
                    path: '',
                    redirect: '/overview', // default child route
                },
                {
                    path: 'overview',
                    name: 'Overview',
                    component: OverviewTab,
                },
                {
                    path: 'ca',
                    name: 'CA',
                    component: CATab,
                },
                {
                    path: 'users',
                    name: 'Users',
                    component: UserTab,
                },
                {
                    path: 'groups',
                    name: 'Groups',
                    component: GroupsTab,
                },
                {
                    path: 'audit',
                    name: 'Audit',
                    component: AuditTab,
                },
                {
                    path: 'acme',
                    name: 'ACME',
                    component: AcmeTab,
                },
                {
                    path: 'letsencrypt',
                    name: 'LetsEncrypt',
                    component: AcmeClientTab,
                },
                {
                    path: 'profile',
                    name: 'Profile',
                    component: ProfileTab,
                },
                {
                    path: 'settings',
                    name: 'Settings',
                    component: SettingsTab,
                },
            ],
        },
    ],
});

router.beforeEach(authGuard);

export default router;
