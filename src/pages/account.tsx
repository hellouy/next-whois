import { GetServerSideProps } from "next";

/**
 * /account — legacy redirect to /dashboard?tab=account
 *
 * Email templates reference /account for the "Manage Account" link.
 * This page simply redirects users to the dashboard's Account tab.
 */
export default function AccountRedirect() {
  return null;
}

export const getServerSideProps: GetServerSideProps = async () => {
  return {
    redirect: {
      destination: "/dashboard?tab=account",
      permanent: false,
    },
  };
};
