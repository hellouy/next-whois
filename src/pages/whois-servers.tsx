import { GetServerSideProps } from "next";

export const getServerSideProps: GetServerSideProps = async () => {
  return {
    redirect: {
      destination: "/tlds",
      permanent: false,
    },
  };
};

export default function WhoisServersRedirect() {
  return null;
}
